using System.Text;

namespace MiyoMacroSentinel.Parsers.Services;

public static class TextExtraction
{
    public static async Task<string> ReadTextPrefixAsync(string filePath, int maxBytes, CancellationToken cancellationToken)
    {
        var bytes = await ReadBytesPrefixAsync(filePath, maxBytes, cancellationToken).ConfigureAwait(false);
        return DecodeBestEffort(bytes);
    }

    public static async Task<byte[]> ReadBytesPrefixAsync(string filePath, int maxBytes, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var length = (int)Math.Min(maxBytes, stream.Length);
        var buffer = new byte[length];
        var total = 0;
        while (total < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, length - total), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total == buffer.Length ? buffer : buffer[..total];
    }

    public static string DecodeBestEffort(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Encoding.Unicode.GetString(bytes);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Encoding.BigEndianUnicode.GetString(bytes);
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }

    public static string ExtractAsciiAndUnicodeStrings(byte[] bytes, int minLength = 4, int maxChars = 250_000)
    {
        var builder = new StringBuilder();
        AppendAsciiStrings(bytes, minLength, builder, maxChars);
        AppendUtf16LeStrings(bytes, minLength, builder, maxChars);
        return builder.ToString();
    }

    private static void AppendAsciiStrings(byte[] bytes, int minLength, StringBuilder builder, int maxChars)
    {
        var current = new StringBuilder();
        foreach (var b in bytes)
        {
            if (b is >= 0x20 and <= 0x7E or 0x09)
            {
                current.Append((char)b);
            }
            else
            {
                Flush(current, minLength, builder, maxChars);
                if (builder.Length >= maxChars)
                {
                    return;
                }
            }
        }

        Flush(current, minLength, builder, maxChars);
    }

    private static void AppendUtf16LeStrings(byte[] bytes, int minLength, StringBuilder builder, int maxChars)
    {
        var current = new StringBuilder();
        for (var i = 0; i + 1 < bytes.Length; i += 2)
        {
            var codeUnit = bytes[i] | (bytes[i + 1] << 8);
            if (codeUnit is >= 0x20 and <= 0x7E or 0x09)
            {
                current.Append((char)codeUnit);
            }
            else
            {
                Flush(current, minLength, builder, maxChars);
                if (builder.Length >= maxChars)
                {
                    return;
                }
            }
        }

        Flush(current, minLength, builder, maxChars);
    }

    private static void Flush(StringBuilder current, int minLength, StringBuilder output, int maxChars)
    {
        if (current.Length >= minLength)
        {
            output.AppendLine(current.ToString());
        }

        current.Clear();
        if (output.Length > maxChars)
        {
            output.Length = maxChars;
        }
    }
}
