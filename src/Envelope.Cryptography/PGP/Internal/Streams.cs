using Org.BouncyCastle.Utilities.IO;

namespace Envelope.Cryptography.PGP.Internal;

internal static class Streams
{
	private const int BufferSize = 512;

	public static void Drain(Stream inStr)
	{
		byte[] bs = new byte[BufferSize];
		while (0 < inStr.Read(bs, 0, bs.Length))
		{
		}
	}

	public static byte[] ReadAll(Stream inStr)
	{
		var buf = new MemoryStream();
		PipeAll(inStr, buf);
		return buf.ToArray();
	}

	public static byte[] ReadAllLimited(Stream inStr, int limit)
	{
		var buf = new MemoryStream();
		PipeAllLimited(inStr, limit, buf);
		return buf.ToArray();
	}

	public static int ReadFully(Stream inStr, byte[] buf)
		=> ReadFully(inStr, buf, 0, buf.Length);

	public static int ReadFully(Stream inStr, byte[] buf, int off, int len)
	{
		int totalRead = 0;
		while (totalRead < len)
		{
			int numRead = inStr.Read(buf, off + totalRead, len - totalRead);
			if (numRead < 1)
				break;
			totalRead += numRead;
		}
		return totalRead;
	}

	public static void PipeAll(Stream inStr, Stream outStr)
	{
		byte[] bs = new byte[BufferSize];
		int numRead;
		while (0 < (numRead = inStr.Read(bs, 0, bs.Length)))
		{
			outStr.Write(bs, 0, numRead);
		}
	}

	/// <summary>
	/// Pipe all bytes from <c>inStr</c> to <c>outStr</c>, throwing <c>StreamFlowException</c> if greater
	/// than <c>limit</c> bytes in <c>inStr</c>.
	/// </summary>
	/// <param name="inStr">
	/// A <see cref="Stream"/>
	/// </param>
	/// <param name="limit">
	/// A <see cref="System.Int64"/>
	/// </param>
	/// <param name="outStr">
	/// A <see cref="Stream"/>
	/// </param>
	/// <returns>The number of bytes actually transferred, if not greater than <c>limit</c></returns>
	/// <exception cref="IOException"></exception>
	public static long PipeAllLimited(Stream inStr, long limit, Stream outStr)
	{
		byte[] bs = new byte[BufferSize];
		long total = 0;
		int numRead;
		while (0 < (numRead = inStr.Read(bs, 0, bs.Length)))
		{
			if ((limit - total) < numRead)
				throw new StreamOverflowException("Data Overflow");

			total += numRead;
			outStr.Write(bs, 0, numRead);
		}
		return total;
	}

	/// <exception cref="IOException"></exception>
	public static void WriteBufTo(MemoryStream buf, Stream output)
	{
		buf.WriteTo(output);
	}

	public static async Task DrainAsync(Stream inStr, CancellationToken cancellationToken)
	{
		byte[] bs = new byte[BufferSize];
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < await inStr.ReadAsync(bs, 0, bs.Length, cancellationToken)) { }
#elif NET6_0_OR_GREATER
		while (0 < await inStr.ReadAsync(bs, cancellationToken)) { }
#endif
	}

	public static async Task<byte[]> ReadAllAsync(Stream inStr, CancellationToken cancellationToken)
	{
		var buf = new MemoryStream();
		await PipeAllAsync(inStr, buf, cancellationToken);
		return buf.ToArray();
	}

	public static async Task<byte[]> ReadAllLimitedAsync(Stream inStr, int limit, CancellationToken cancellationToken)
	{
		var buf = new MemoryStream();
		await PipeAllLimitedAsync(inStr, limit, buf, cancellationToken);
		return buf.ToArray();
	}

	public static Task<int> ReadFullyAsync(Stream inStr, byte[] buf, CancellationToken cancellationToken)
		=> ReadFullyAsync(inStr, buf, 0, buf.Length, cancellationToken);

	public static async Task<int> ReadFullyAsync(Stream inStr, byte[] buf, int off, int len, CancellationToken cancellationToken)
	{
		int totalRead = 0;
		while (totalRead < len)
		{
#if NETSTANDARD2_0 || NETSTANDARD2_1
			int numRead = await inStr.ReadAsync(buf, off + totalRead, len - totalRead, cancellationToken);
#elif NET6_0_OR_GREATER
			int numRead = await inStr.ReadAsync(buf.AsMemory(off + totalRead, len - totalRead), cancellationToken);
#endif
			if (numRead < 1)
				break;
			totalRead += numRead;
		}
		return totalRead;
	}

	public static async Task PipeAllAsync(Stream inStr, Stream outStr, CancellationToken cancellationToken)
	{
		byte[] bs = new byte[BufferSize];
		int numRead;
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < (numRead = await inStr.ReadAsync(bs, 0, bs.Length, cancellationToken)))
		{
			await outStr.WriteAsync(bs, 0, numRead, cancellationToken);
		}
#elif NET6_0_OR_GREATER
		while (0 < (numRead = await inStr.ReadAsync(bs, cancellationToken)))
		{
			await outStr.WriteAsync(bs.AsMemory(0, numRead), cancellationToken);
		}
#endif
	}

	public static async Task<long> PipeAllLimitedAsync(Stream inStr, long limit, Stream outStr, CancellationToken cancellationToken)
	{
		byte[] bs = new byte[BufferSize];
		long total = 0;
		int numRead;
#if NETSTANDARD2_0 || NETSTANDARD2_1
		while (0 < (numRead = await inStr.ReadAsync(bs, 0, bs.Length, cancellationToken)))
		{
			if ((limit - total) < numRead)
				throw new StreamOverflowException("Data Overflow");

			total += numRead;
			await outStr.WriteAsync(bs, 0, numRead, cancellationToken);
		}
#elif NET6_0_OR_GREATER
		while (0 < (numRead = await inStr.ReadAsync(bs, cancellationToken)))
		{
			if ((limit - total) < numRead)
				throw new StreamOverflowException("Data Overflow");

			total += numRead;
			await outStr.WriteAsync(bs.AsMemory(0, numRead), cancellationToken);
		}
#endif
		return total;
	}
}
