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


import static org.czeal.rfc3986.Utils.isHexDigit;
import static org.czeal.rfc3986.Utils.newIAE;
import java.util.Arrays;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates the {@code host} component of a URI reference as an IPv6 address according
 * to the syntax defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">
 * RFC 3986, Appendix A. Collected ABNF for URI</a> as follows.
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * IPv6address =                            6( h16 ":" ) ls32
 *             /                       "::" 5( h16 ":" ) ls32
 *             / [               h16 ] "::" 4( h16 ":" ) ls32
 *             / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
 *             / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
 *             / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
 *             / [ *4( h16 ":" ) h16 ] "::"              ls32
 *             / [ *5( h16 ":" ) h16 ] "::"              h16
 *             / [ *6( h16 ":" ) h16 ] "::"
 *
 * h16         = 1*4HEXDIG
 * ls3         = ( h16 ":" h16 ) / IPv4address
 * IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
 * dec-octet   = DIGIT                 ; 0-9
 *             / %x31-39 DIGIT         ; 10-99
 *             / "1" 2DIGIT            ; 100-199
 *             / "2" %x30-34 DIGIT     ; 200-249
 *             / "25" %x30-35          ; 250-255
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class Ipv6AddressValidator
{
    /**
     * The maximum value for the total bits represented by an IPv6 address value
     * containing double colons.
     */
    private static final int MAX_BITS = 16 * 7;


    /**
     * Validates the {@code host} component of a URI reference as an IPv6 address.
     *
     * @param ipv6Address
     *         An IPv6 address value. Expected to be a value enclosed by the brackets
     *         in a host value.
     *
     * @throws IllegalArgumentException
     *         If the IPv6 Address value is invalid.
     */
    void validate(String ipv6Address)
    {
        // RFC 3986, Appendix A. Collected ABNF for URI
        //
        //   IPv6address =                            6( h16 ":" ) ls32
        //               /                       "::" 5( h16 ":" ) ls32
        //               / [               h16 ] "::" 4( h16 ":" ) ls32
        //               / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
        //               / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
        //               / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
        //               / [ *4( h16 ":" ) h16 ] "::"              ls32
        //               / [ *5( h16 ":" ) h16 ] "::"              h16
        //               / [ *6( h16 ":" ) h16 ] "::"

        // Divide the string into up-to two parts by the first "::".
        String[] parts = ipv6Address.split("::", 2);

        if (parts.length == 1)
        {
            // The number of the parts is 1, it means the host value doesn't
            // contain "::".
            validateIpv6WithoutDoubleColons(ipv6Address);
            return;
        }

        if (parts.length == 2)
        {
            // The number of the parts is 2, it means the host value contains
            // "::".
            validateIpv6WithDoubleColons(parts[0], parts[1], ipv6Address);
            return;
        }

        // We won't reach here.
    }


    private void validateIpv6WithoutDoubleColons(String ipv6Address)
    {
        // In this case, the input string must follow the following syntax.
        //
        //   6( h16 ":" ) ( h16 ":" h16 )
        //   6( h16 ":" ) IPv4address

        // Divide the input string by ':'.
        String[] segments = ipv6Address.split(":", -1);

        if (segments.length == 7)
        {
            // This means the input string contains 6 colons. Then, the input
            // string must follow the syntax below.
            //
            //   6( h16 ":" ) IPv4address
            //
            validateH16Array(Arrays.copyOfRange(segments, 0, 6), ipv6Address);
            validate(segments[6]);
            return;
        }

        if (segments.length == 8)
        {
            // This means the input string contains 7 colons. Then, the input
            // string must follow the syntax below.
            //
            //   6( h16 ":" ) ( h16 ":" h16 )
            //
            validateH16Array(segments, ipv6Address);
            return;
        }

        // The number of segments contained in the host value is incorrect.
        throw newIAE(
            "The host value \"[%s]\" is invalid because the content enclosed " +
            "by brackets does not form a valid IPv6 address due to an incorrect " +
            "number of segments.", ipv6Address);
    }


    private void validateIpv6WithDoubleColons(
        String valueBeforeDoubleColons, String valueAfterDoubleColons, String value)
    {
        // In this case, the input string contains "::", then it must follow one
        // of the below syntaxes.
        //
        //                         "::" 6( h16 ":" ) h16
        //   [               h16 ] "::" 5( h16 ":" ) h16
        //   [ *1( h16 ":" ) h16 ] "::" 4( h16 ":" ) h16
        //   [ *2( h16 ":" ) h16 ] "::" 3( h16 ":" ) h16
        //   [ *3( h16 ":" ) h16 ] "::" 2( h16 ":" ) h16
        //   [ *4( h16 ":" ) h16 ] "::"    h16 ":"   h16
        //   [ *5( h16 ":" ) h16 ] "::"    h16
        //   [ *6( h16 ":" ) h16 ] "::"
        //                         "::" 5( h16 ":" ) IPv4address
        //   [               h16 ] "::" 4( h16 ":" ) IPv4address
        //   [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) IPv4address
        //   [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) IPv4address
        //   [ *3( h16 ":" ) h16 ] "::"    h16 ":"   IPv4address
        //   [ *4( h16 ":" ) h16 ] "::"              IPv4address

        // Check the value before "::".
        int bitsBeforeDoubleColons =
            checkValueBeforeDoubleColons(valueBeforeDoubleColons, value);

        // Check the value after "::".
        int bitsAfterDoubleColons =
            checkValueAfterDoubleColons(valueAfterDoubleColons, value);

        // The total bits.
        int totalBits = bitsBeforeDoubleColons + bitsAfterDoubleColons;

        // Ensure the total bits does not exceed the maximum value.
        if (totalBits > MAX_BITS)
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPv6 address, exceeding the " +
                "maximum limit of 128 bits.", value);
        }
    }


    private int checkValueBeforeDoubleColons(String value, String enclosed)
    {
        if (value.isEmpty())
        {
            // The first part is empty. Return 0 as the bits represented by the
            // first part.
            return 0;
        }

        // Divide the part with ":".
        String[] segments = value.split(":", -1);

        // Ensure each segment is H16.
        validateH16Array(segments, enclosed);

        // Return the total bits represented by the first part.
        return 16 * segments.length;
    }


    private int checkValueAfterDoubleColons(String part, String enclosed)
    {
        if (part.isEmpty())
        {
            // The second part is empty. Return 0 as the bits represented by the
            // second part.
            return 0;
        }

        // Divide the segment with ":".
        String[] segments = part.split(":", -1);

        try
        {
            // Try to ensure all the segment parts are 16-bit pieces.
            validateH16Array(segments, enclosed);

            // Calculate the total bits represented by the second part.
            return 16 * segments.length;
        }
        catch (IllegalArgumentException e)
        {
            // If the check above fails, ensure all the segments except for the
            // last segment are H16 and the last segment is ipv4.
            validateH16Array(Arrays.copyOfRange(segments, 0, segments.length - 1), enclosed);
            new Ipv4AddressValidator().validate(segments[segments.length - 1]);

            // Calculate the total bits represented by the second part.
            return 16 * (segments.length - 1) + 32;
        }
    }


    private void validateH16Array(String[] segments, String enclosed)
    {
        // Ensure each segment is a 16-bit piece.
        for (int i = 0; i < segments.length; i++)
        {
            validateH16(segments[i], enclosed);
        }
    }


    private void validateH16(String segment, String enclosed)
    {
        // Ensure the segment is not empty.
        if (segment.isEmpty())
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPv6 address due to an empty " +
                "segment.", enclosed);
        }

        // Ensure the length of the segment doesn't exceed 4.
        if (segment.length() > 4)
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPv6 address due to the segment " +
                "\"%s\" exceeding the maximum limit of 4 characters.", enclosed, segment);
        }

        // Ensure each character in the segment is a hex digit.
        for (int i = 0; i < segment.length(); i++)
        {
            char c = segment.charAt(i);

            if (!isHexDigit(c))
            {
                throw newIAE(
                    "The host value \"[%s]\" is invalid because the content enclosed " +
                    "by brackets does not form a valid IPv6 address due to the segment \"%s\", " +
                    "containing an invalid character \"%s\" at the index %d.", enclosed, segment, c, i);
            }
        }
    }
}
