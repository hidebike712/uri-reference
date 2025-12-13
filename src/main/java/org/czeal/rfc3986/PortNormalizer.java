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


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Normalizes the <code>"port"</code> component of a URI reference.
 * </p>
 *
 * <p>
 * The normalization is performed according to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
 * RFC 3986, Section 6: Normalization and Comparison</a>.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6"> RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class PortNormalizer
{
    /**
     * Normalize a <code>"port"</code> based on <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
     * RFC 3986, Section 6: Normalization and Comparison</a>.
     *
     * @param port
     *         A port value.
     *
     * @param normalizedScheme
     *         The normalized scheme of a URI reference containing the authority.
     *         Expected to be not {@code null}.
     *
     * @return
     *         An integer value representing the normalized port.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     *      Section 6: Normalization and Comparison</a>
     */
    int normalize(int port, String normalizedScheme)
    {
        // Normalize the port value for the scheme based on the following
        // requirement.
        //
        //   RFC 3986, 6.2.3. Scheme-Based Normalization
        //
        //     In general, a URI that uses the generic syntax for authority
        //     with an empty path should be normalized to a path of "/".
        //     Likewise, an explicit ":port", for which the port is empty
        //     or the default for the scheme, is equivalent to one where
        //     the port and its ":" delimiter are elided and thus should
        //     be removed by scheme-based normalization.

        if ((port == -1) || isDefaultPortForScheme(port, normalizedScheme))
        {
            return -1;
        }

        return port;
    }


    private boolean isDefaultPortForScheme(int port, String scheme)
    {
        if ("http".equals(scheme))
        {
            // Check if the port value is 80, which is the default value
            // for "http".
            return port == 80;
        }

        return false;
    }
}
