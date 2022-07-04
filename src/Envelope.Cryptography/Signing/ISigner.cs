using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Envelope.Cryptography.Signing;

public interface ISigner
{
	MemoryStream SignPdf(string pdfBase64, X509Certificate2 certificate);
	MemoryStream SignPdf(byte[] pdfBytes, X509Certificate2 certificate);
	MemoryStream SignPdf(Stream pdfStream, X509Certificate2 certificate);
	MemoryStream SignXml(string xml, X509Certificate2 certificate);
	MemoryStream SignXml(Stream xmlStream, X509Certificate2 certificate);
	MemoryStream SignXml(XmlDocument xmlDocument, X509Certificate2 certificate);
}
