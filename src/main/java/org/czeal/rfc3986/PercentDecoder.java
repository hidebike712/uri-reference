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


import static org.czeal.rfc3986.Utils.newIAE;
import static org.czeal.rfc3986.Utils.newNPE;
import java.nio.CharBuffer;
import java.nio.charset.Charset;


/**
 * Decodes percent-encoded values in a given string.
 *
 * <p>
 * The following is examples of the usage.
 * </p>
 *
 * <p>Examples:</p>
 * <pre>{@code
 * // Decode some percent-encoded values.
 * PercentDecoder.decode("%41BC", StandardCharset.UTF_8); // "ABC"
 * PercentDecoder.decode("%C3%80BC", StandardCharset.UTF_8); // "ÀBC"
 * }</pre>
 *
 * @author Hideki Ikeda
 */
class PercentDecoder extends PercentEncodedStringProcessor
{
    /**
     * Decode percent-encoded values contained in the given string.
     *
     * @param input
     *         A string containing percent-encoded values to decode.
     *
     * @param charset
     *         The charset to be used for decoding values.
     *
     * @return
     *         The decoded string.
     *
     * @throws NullPointerException
     *         If the input value is null.
     *
     * @throws IllegalArgumentException
     *         If the input value has invalid percent-encoded values that can not
     *         be decoded.
     */
    static String decode(String input, Charset charset)
    {
        return new PercentDecoder().process(input, charset);
    }


    /**
     * The private constructor.
     */
    private PercentDecoder()
    {
    }


    private String process(String input, Charset charset)
    {
        // Validate the input.
        validate(input, charset);

        // Process the input.
        return process(input, charset, new StringBuilder());
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


    @Override
    protected void onDecoded(
        Charset charset, StringBuilder outputBuilder, CharBuffer buffer)
    {
        outputBuilder.append(buffer);
    }


    @Override
    protected void onNonPercent(
        String input, StringBuilder outputBuilder, char c, int index)
    {
        outputBuilder.append(c);
    }


    @Override
    protected IllegalArgumentException onMalformedPercentEncodedValue(
        String input, int index)
    {
        return newIAE(
            "The percent symbol \"%%\" at the index %d in the input value \"%s\" " +
            "is not followed by two characters.", index, input);
    }


    @Override
    protected IllegalArgumentException onInvalidHexDigit(
        String input, char hexDigit, int index)
    {
        return newIAE(
            "The character \"%s\" at the index %d in the value \"%s\" is invalid " +
            "as a hex digit.", hexDigit, index, input);
    }


    @Override
    protected IllegalArgumentException onDecodeFailed(String input, Info info)
    {
        return newIAE(
            "Failed to decode \"%s\" in the value \"%s\".", info.getString(), input);
    }
}
