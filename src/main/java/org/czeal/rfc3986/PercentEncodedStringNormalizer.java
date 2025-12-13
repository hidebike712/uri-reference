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


import static org.czeal.rfc3986.Utils.newISE;
import java.nio.CharBuffer;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * An abstract class for normalizing a URI component (scheme, host, etc) based on
 * the following requirements in RFC 3986.
 *
 * <blockquote>
 * <pre>
 * <u>RFC 3986, 6.2.2.1. Case Normalization</u>
 *
 * For all URIs, the hexadecimal digits within a percent-encoding triplet (e.g.,
 * "%3a" versus "%3A") are case-insensitive and therefore should be normalized to
 * use uppercase letters for the digits A-F.
 *
 * When a URI uses components of the generic syntax, the component syntax equivalence
 * rules always apply; namely, that the scheme and host are case-insensitive and
 * therefore should be normalized to lowercase. For example, the URI &lt;HTTP://www.EXAMPLE.com/&gt; is
 * equivalent to &lt;http://www.example.com/&gt;. The other generic syntax components
 * are assumed to be case-sensitive unless specifically defined otherwise by the
 * scheme (see Section 6.2.3).
 * </pre>
 * <pre>
 * <u>RFC 3986, 6.2.2.2. Percent-Encoding Normalization</u>
 *
 * ... In addition to the case normalization issue noted above, some URI producers
 * percent-encode octets that do not require percent-encoding, resulting in URIs
 * that are equivalent to their non-encoded counterparts. These URIs should be
 * normalized by decoding any percent-encoded octet that corresponds to an unreserved
 * character, as described in Section 2.3.
 * </pre>
 * </blockquote>
 *
 * @author Hideki Ikeda
 */
abstract class PercentEncodedStringNormalizer extends PercentEncodedStringProcessor
{
    @Override
    protected void onDecoded(
        Charset charset, StringBuilder outputBuilder, CharBuffer buffer)
    {
        // Convert the decoded value (char buffer) to a string.
        String normalized = buffer.toString();

        // If lower-case is required.
        if (toLowerCase())
        {
            // Convert the string to lower-case.
            normalized = normalized.toLowerCase();
        }

        // Percent-encode back the characters, except for the unreserved characters
        // (e.g. alphabets).
        normalized = PercentEncoder.encode(normalized, charset);

        // Save the normalized value to the output builder.
        outputBuilder.append(normalized);
    }


    @Override
    protected void onNonPercent(
        String input, StringBuilder outputBuilder, char c, int index)
    {
        // Convert the value to lower-case if it's required; otherwise, use the
        // value as-is.
        char normalized = toLowerCase() ? Character.toLowerCase(c) : c;

        // Save the normalized value to the output builder.
        outputBuilder.append(normalized);
    }


    @Override
    protected IllegalArgumentException onMalformedPercentEncodedValue(
        String input, int index)
    {
        // This won't happen.
        throw newISE("onMalformedPercentEncodedValue() is not supposed to be called.");
    }


    @Override
    protected IllegalArgumentException onInvalidHexDigit(
        String input, char hexDigit, int index)
    {
        // This won't happen.
        throw newISE("onInvalidHexDigit() is not supposed to be called.");
    }


    @Override
    protected IllegalArgumentException onDecodeFailed(String input, Info info)
    {
        // This won't happen.
        throw newISE("onDecodeFailed(input) is not supposed to be called.");
    }


    /**
     * Whether or not lower-case characters are required for the component.
     *
     * @return
     *         Whether or not lower-case characters are required for the component.
     */
    protected abstract boolean toLowerCase();
}
