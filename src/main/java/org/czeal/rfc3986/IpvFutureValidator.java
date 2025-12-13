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
import static org.czeal.rfc3986.Utils.isSubdelim;
import static org.czeal.rfc3986.Utils.isUnreserved;
import static org.czeal.rfc3986.Utils.newIAE;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates the {@code host} component of a URI reference as an IPvFuture address
 * according to the syntax defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">
 * RFC 3986, Appendix A. Collected ABNF for URI</a> as follows.
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class IpvFutureValidator
{
    /**
     * Validates a value as an IPvFuture address.
     *
     * @param ipvFuture
     *         An IPvFuture address value. Expected to be a value enclosed by the
     *         brackets in a host value.
     *
     * @throws IllegalArgumentException
     *         If the IPvFuture is invalid.
     */
    void validate(String ipvFuture)
    {
        // Ensure the host value is not empty.
        if (ipvFuture.isEmpty())
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPvFuture address as it is empty.",
                ipvFuture);
        }

        // Divide the host value into up-to two segments by the first period.
        String[] segments = ipvFuture.split("\\.", 2);

        // If the number of the segments is 1, it means the host value doesn't
        // contain a period.
        if (segments.length == 1)
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPvFuture address due to " +
                "missing periods.", ipvFuture);
        }

        // Check the first segment of the host.
        validateFirstSegmentOfIpvFuture(ipvFuture, segments[0]);

        // Check the second segment of the host.
        validateSecondSegmentOfIpvFuture(ipvFuture, segments[1]);
    }


    private void validateFirstSegmentOfIpvFuture(String enclosed, String firstSegment)
    {
        // Check if the first segment starts with "v" or "V".
        boolean isValid = firstSegment.startsWith("v") || firstSegment.startsWith("V");

        // Ensure the first segment starts with 'v' or 'V'.
        if (!isValid)
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPvFuture address due to missing " +
                "a version indicator 'v' (or 'V').", enclosed);
        }

        // Extract the version value (= characters after the first 'v') from the
        // first segment .
        String version = firstSegment.substring(1);

        // Ensure the version is not empty.
        if (version.isEmpty())
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPvFuture address due to missing " +
                "its version.", enclosed);
        }

        // Ensure all the characters in the version value are valid.
        for (int i = 0; i < version.length(); i++)
        {
            char c = version.charAt(i);

            if (!isHexDigit(c))
            {
                throw newIAE(
                    "The host value \"[%s]\" is invalid because the content enclosed " +
                    "by brackets does not form a valid IPvFuture address due to " +
                    "an invalid version \"%s\", containing an invalid character " +
                    "\"%s\" at the index %d.", enclosed, version, c, i);
            }
        }
    }


    private void validateSecondSegmentOfIpvFuture(String enclosed, String secondSegment)
    {
        // Ensure the second segment is not empty.
        if (secondSegment.isEmpty())
        {
            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPvFuture address as there is " +
                "no content following the first period.", enclosed);
        }

        // Ensure all the characters in the second segment are valid.
        for (int i = 0; i < secondSegment.length(); i++)
        {
            char c = secondSegment.charAt(i);

            if (isUnreserved(c) || isSubdelim(c) || c == ':')
            {
                continue;
            }

            throw newIAE(
                "The host value \"[%s]\" is invalid because the content enclosed " +
                "by brackets does not form a valid IPvFuture address due to the " +
                "segment after the first period \"%s\", containing an invalid " +
                "character \"%c\" at the index %d.", enclosed, secondSegment, c, i);
        }
    }
}
