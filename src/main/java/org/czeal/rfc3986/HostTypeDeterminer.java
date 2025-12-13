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


import static org.czeal.rfc3986.HostType.IPV4;
import static org.czeal.rfc3986.HostType.IPV6;
import static org.czeal.rfc3986.HostType.IPVFUTURE;
import static org.czeal.rfc3986.HostType.REGNAME;
import static org.czeal.rfc3986.Utils.newIAE;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Determines the host type. Possible host type values are {@link HostType#REGNAME REGNAME},
 * {@link HostType#IPV4 IPV4}, {@link HostType#IPV6 IPV6} and {@link HostType#IPVFUTURE IPVFUTURE}.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6"> RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class HostTypeDeterminer
{
    /**
     * Determines the host type. Possible host type values are {@link HostType#REGNAME REGNAME},
     * {@link HostType#IPV4 IPV4}, {@link HostType#IPV6 IPV6} and {@link HostType#IPVFUTURE IPVFUTURE}.
     *
     * @param value
     *         A {@code host} value.
     *
     * @param charset
     *         The charset used for percent-encoding some characters (e.g. reserved
     *         characters) contained in the {@code host} parameter.
     *
     * @return
     *         The type of the host value.
     */
    HostType determine(String value, Charset charset)
    {
        // If the host is null or empty.
        if (value == null || value.isEmpty())
        {
            // The host type is determined as a reg-name.
            return REGNAME;
        }

        // If the host value starts with '[', indicating the host value being an
        // IP-literal.
        if (value.startsWith("["))
        {
            return determineHostTypeForIpLiteral(value);
        }

        try
        {
            // Validate the host value as an IPv4 address.
            new Ipv4AddressValidator().validate(value);

            // The host type is determined as an IPv4 address.
            return IPV4;
        }
        catch (Throwable t)
        {
            // If the check above fails, validate the host value as a reg-name.
            new RegNameValidator().validate(value, charset);

            // The host type is determined as a reg-name.
            return REGNAME;
        }
    }


    private HostType determineHostTypeForIpLiteral(String value)
    {
        // Ensure the host value ends with ']'.
        if (!value.endsWith("]"))
        {
            throw newIAE(
                "The host value \"%s\" start with \"[\" but doesn't end with \"]\".",
                value);
        }

        // Extract the content enclosed by brackets.
        String enclosed = value.substring(1, value.length() - 1);

        try
        {
            // Validate the host value as an IPv6 address.
            new Ipv6AddressValidator().validate(enclosed);

            // The host type is determined as an IPv6 address.
            return IPV6;
        }
        catch (Throwable t)
        {
            // If the check above fails, validate the host value as an IPvFuture
            // address.
            new IpvFutureValidator().validate(enclosed);

            // The host type is determined as an IPvFuture address.
            return IPVFUTURE;
        }
    }
}
