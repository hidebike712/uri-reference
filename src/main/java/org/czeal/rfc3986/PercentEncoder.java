/*
 * Copyright (C) 2024 Hideki Ikeda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.czeal.rfc3986;


import static org.czeal.rfc3986.Utils.isUnreserved;
import static org.czeal.rfc3986.Utils.newIAE;
import static org.czeal.rfc3986.Utils.newNPE;
import static org.czeal.rfc3986.Utils.toHexDigit;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.util.Set;


/**
 * An encoder that percent-encodes characters in a given string.
 *
 * <p>Examples:</p>
 * <pre>{@code
 * // Create an instance of PercentEncoder using UTF-8.
 * PercentEncoder encoder = new PercentEncoder(StandardCharset.UTF_8);
 *
 * // Encode some string values.
 * PercentEncoder.encode("ÀBC", StandardCharset.UTF_8); // output: "%C3%80BC"
 * PercentEncoder.encode("ABC", StandardCharset.UTF_8); // output: "ABC" (Unreserved characters are not encoded.)
 * }</pre>
 *
 * @author Hideki Ikeda
 */
class PercentEncoder
{
    /**
     * Percent encode the given input with the specified charset. This method will
     * not encode unreserved characters defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">
     * RFC 3986, 2.3. Unreserved Characters</a>.
     *
     * @param input
     *         Required. The input to encode.
     *
     * @param charset
     *         Required. The charset to be used for encoding values.
     *
     * @return
     *         The encoded string.
     *
     * @throws NullPointerException
     *         If the value of {@code input} or {@code charset} is {@code null}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">RFC 3986,
     *      2.3. Unreserved Characters</a>
     */
    static String encode(String input, Charset charset)
    {
        return encode(input, charset, null);
    }


    /**
     * Percent-encode the given input with the specified charset. This method
     * will not encode characters contained in {@code preservedChars} parameter.
     *
     * @param input
     *         Required. The input to encode.
     *
     * @param charset
     *         Required. The charset to be used for encoding values.
     *
     * @param preservedChars
     *         Optional. The character set to preserve.
     *
     * @return
     *         The encoded string.
     *
     * @throws NullPointerException
     *         If the value of {@code input} or {@code charset} is {@code null}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">
     *      RFC 3986, 2.3. Unreserved Characters</a>
     */
    static String encode(
        String input, Charset charset, Set<Character> preservedChars)
    {
        return new PercentEncoder().process(input, charset, preservedChars);
    }


    /**
     * The private constructor.
     */
    private PercentEncoder() {}


    /**
     * Percent-encode the given input with the specified charset. This method will
     * not encode characters contained in {@code preservedChars} parameter.
     *
     * @param input
     *         The input to percent-encode.
     *
     * @param charset
     *         The charset to be used for encoding values.
     *
     * @param preservedChars
     *          The character set to preserve.
     *
     * @return
     *         The encoded string.
     *
     * @throws NullPointerException
     *         If the value of {@code input} or {@code charset} is {@code null}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-2.3">
     *      RFC 3986, 2.3. Unreserved Characters</a>
     */
    private String process(
        String input, Charset charset, Set<Character> preservedChars)
    {
        // Validate the arguments.
        validate(input, charset);

        // The builder for the resultant string.
        StringBuilder outputBuilder = new StringBuilder();

        // Encode each character in the input.
        for (int i = 0; i < input.length(); i++)
        {
            // The i-th character of the input value.
            char c = input.charAt(i);

            // If the character should be preserved.
            if (isPreserved(preservedChars, c))
            {
                // Preserve the character as-is.
                outputBuilder.append(c);
            }
            else
            {
                // Encode the character with the charset and append it.
                outputBuilder.append(encode(charset, c));
            }
        }

        // Build the output string.
        return outputBuilder.toString();
    }


    private void validate(String input, Charset charset)
    {
        // Ensure the input is not null.
        if (input == null)
        {
            throw newNPE("A input must not be null.");
        }

        // Ensure the charset is not null.
        if (charset == null)
        {
            throw newNPE("A charset must not be null.");
        }
    }


    private boolean isPreserved(Set<Character> preservedChars, char c)
    {
        // If the preservedChars is not null, check if the character is
        // contained in preservedChars; otherwise, check if the character
        // is an unreserved character or not.
        return preservedChars != null ? preservedChars.contains(c) : isUnreserved(c);
    }


    private char[] encode(Charset charset, char c)
    {
        // Encode the character into bytes using the charset.
        byte[] bytes = toBytes(charset, c);

        // The output array.
        char[] chars = new char[3 * bytes.length];

        // For each byte.
        for (int i = 0; i < bytes.length; i++)
        {
            // Create a percent-encoded value.
            chars[3 * i    ] = '%';
            chars[3 * i + 1] = toHexDigit((bytes[i] & 0xF0) >> 4);
            chars[3 * i + 2] = toHexDigit(bytes[i] & 0xF);
        }

        // Return the output array.
        return chars;
    }


    private byte[] toBytes(Charset charset, char c)
    {
        try
        {
            // Encode the character using the charset and then convert it to an
            // byte array.
            return charset.newEncoder()
                .encode( CharBuffer.wrap(String.valueOf(c)) )
                .array();
        }
        catch (CharacterCodingException e)
        {
            // Failed to encode the character.
            throw newIAE("Failed to encode the character \"" + c + "\".");
        }
    }
}
