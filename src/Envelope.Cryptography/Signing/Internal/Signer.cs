using iText.Kernel.Pdf;
using iText.Signatures;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Envelope.Cryptography.Signing.Internal;

internal class Signer : ISigner
{
	#region iTextSharp

	//public MemoryStream SignPdf(string pdfBase64, X509Certificate2 certificate)
	//{
	//	if (string.IsNullOrWhiteSpace(pdfBase64))
	//		throw new ArgumentNullException(nameof(pdfBase64));

	//	if (certificate == null)
	//		throw new ArgumentNullException(nameof(certificate));

	//	var pdfBytes = Convert.FromBase64String(pdfBase64);
	//	var pdfReader = new iTextSharp.text.pdf.PdfReader(pdfBytes);
	//	return SignPdf(pdfReader, certificate);
	//}

	//public MemoryStream SignPdf(byte[] pdfBytes, X509Certificate2 certificate)
	//{
	//	if (pdfBytes == null)
	//		throw new ArgumentNullException(nameof(pdfBytes));

	//	if (certificate == null)
	//		throw new ArgumentNullException(nameof(certificate));

	//	var pdfReader = new iTextSharp.text.pdf.PdfReader(pdfBytes);
	//	return SignPdf(pdfReader, certificate);
	//}

	//public MemoryStream SignPdf(Stream pdfStream, X509Certificate2 certificate)
	//{
	//	if (pdfStream == null)
	//		throw new ArgumentNullException(nameof(pdfStream));

	//	if (certificate == null)
	//		throw new ArgumentNullException(nameof(certificate));

	//	var pdfReader = new iTextSharp.text.pdf.PdfReader(pdfStream);
	//	return SignPdf(pdfReader, certificate);
	//}

	//private static MemoryStream SignPdf(iTextSharp.text.pdf.PdfReader pdfReader, X509Certificate2 certificate)
	//{
	//	var cp = new Org.BouncyCastle.X509.X509CertificateParser();
	//	var chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(certificate.RawData) };
	//	var externalSignature = new iTextSharp.text.pdf.security.X509Certificate2Signature(certificate, "SHA-1");

	//	using var ms = new MemoryStream();
	//	var pdfStamper = iTextSharp.text.pdf.PdfStamper.CreateSignature(pdfReader, ms, '\0');
	//	var signatureAppearance = pdfStamper.SignatureAppearance;

	//	//here set signatureAppearance at your will
	//	//signatureAppearance.Reason = "Because I can";
	//	//signatureAppearance.Location = "My location";

	//	//VIZUALNY PODPIS:
	//	//signatureAppearance.SignatureGraphic = Image.GetInstance(@"c:\Code\Private\Signer\podpis.png");
	//	//signatureAppearance.SetVisibleSignature(new Rectangle(100, 100, 500, 150), pdfReader.NumberOfPages, "Signature");
	//	//signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION;

	//	iTextSharp.text.pdf.security.MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, iTextSharp.text.pdf.security.CryptoStandard.CMS);

	//	try
	//	{
	//		ms.Flush();
	//	}
	//	catch { }

	//	return ms;
	//}

	#endregion iTextSharp

	public MemoryStream SignPdf(string pdfBase64, X509Certificate2 certificate)
	{
		if (string.IsNullOrWhiteSpace(pdfBase64))
			throw new ArgumentNullException(nameof(pdfBase64));

		if (certificate == null)
			throw new ArgumentNullException(nameof(certificate));

		var pdfBytes = Convert.FromBase64String(pdfBase64);
		using var ms = new MemoryStream(pdfBytes);
		var pdfReader = new PdfReader(ms);
		return SignPdf(pdfReader, certificate);
	}

	public MemoryStream SignPdf(byte[] pdfBytes, X509Certificate2 certificate)
	{
		if (pdfBytes == null)
			throw new ArgumentNullException(nameof(pdfBytes));

		if (certificate == null)
			throw new ArgumentNullException(nameof(certificate));

		using var ms = new MemoryStream(pdfBytes);
		var pdfReader = new PdfReader(ms);
		return SignPdf(pdfReader, certificate);
	}

	public MemoryStream SignPdf(Stream pdfStream, X509Certificate2 certificate)
	{
		if (pdfStream == null)
			throw new ArgumentNullException(nameof(pdfStream));

		if (certificate == null)
			throw new ArgumentNullException(nameof(certificate));

		var pdfReader = new PdfReader(pdfStream);
		return SignPdf(pdfReader, certificate);
	}

	private static MemoryStream SignPdf(PdfReader pdfReader, X509Certificate2 certificate)
	{
		using var ms = new MemoryStream();
		var signer = new PdfSigner(pdfReader, ms, new StampingProperties());

		//visual signature
		//var appearance = signer.GetSignatureAppearance();
		//appearance
		//	.SetReason("nastav reason")
		//	.SetLocation("nastav location")
		//	.SetPageRect(new Rectangle(36, 648, 200, 100))
		//	.SetSignatureGraphic(imageData)
		//	.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION)
		//	.SetPageNumber(1);
		signer.SetFieldName("Signature");

		var cp = new Org.BouncyCastle.X509.X509CertificateParser();
		var chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(certificate.RawData) };

		IExternalSignature pks = new ExternalSignature(certificate);
		signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

		try
		{
			ms.Flush();
		}
		catch { }

		return ms;
	}

	public MemoryStream SignXml(string xml, X509Certificate2 certificate)
	{
		var document = new XmlDocument
		{
			PreserveWhitespace = true
		};
		document.LoadXml(xml);

		return SignXml(document, certificate);
	}

	public MemoryStream SignXml(Stream xmlStream, X509Certificate2 certificate)
	{
		var document = new XmlDocument
		{
			PreserveWhitespace = true
		};
		document.Load(xmlStream);

		return SignXml(document, certificate);
	}

	public MemoryStream SignXml(XmlDocument xmlDocument, X509Certificate2 certificate)
	{
		var signedXml = new SignedXml(xmlDocument)
		{
			SigningKey = certificate.GetRSAPrivateKey()
		};

		var reference = new Reference
		{
			Uri = "",
			DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
		};

		var signatureTransform = new XmlDsigEnvelopedSignatureTransform();
		reference.AddTransform(signatureTransform);

		signedXml.AddReference(reference);
		signedXml.KeyInfo = new KeyInfo();
		signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate, X509IncludeOption.EndCertOnly));
		signedXml.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
		signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
		signedXml.ComputeSignature();

		var xml1 = signedXml.GetXml();
		xmlDocument.DocumentElement?.AppendChild(xmlDocument.ImportNode(xml1, true));
		var ms = new MemoryStream();
		XmlWriter w = XmlWriter.Create(ms);
		xmlDocument.Save(w);
		w.Flush();
		ms.Position = 0L;

		//return new StreamReader((Stream)ms).ReadToEnd();

		return ms;
	}
}
