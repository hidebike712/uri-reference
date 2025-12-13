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


import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Normalizes the {@code authority} component of a URI reference, according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section 6:
 * Normalization and Comparison</a>.
 *
 * <p>
 * Note that the normalization doesn't modify the state of the given {@link Authority}
 * object. Instead, it creates a new {@link Authority} object and initializes it
 * with the normalized {@code authority} information.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.2">RFC 3986,
 *      3.2. Authority</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class AuthorityNormalizer
{
    /**
     * Normalizes the {@code authority} component of a URI reference, according
     * to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     * Section 6: Normalization and Comparison</a>. This method does not modify
     * the state of the original {@link Authority} object on which this method is
     * called. Instead, it creates a new {@link Authority} object with the normalized
     * {@code authority} information.
     *
     * @param authority
     *         An {@link Authority} object to normalize.
     *
     * @param charset
     *         The charset used for percent-encoding some characters (e.g. reserved
     *         characters) contained in the {@code authority} parameter.
     *
     * @param normalizedScheme
     *         The normalized scheme of the URI reference containing the authority.
     *
     * @return
     *         The {@link Authority} object representing the normalized {@code authority}
     *         component.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     *      Section 6: Normalization and Comparison</a>
     */
    Authority normalize(
        Authority authority, Charset charset, String normalizedScheme)
    {
        if (authority == null)
        {
            // The authority does not exist in the original URI reference.
            return null;
        }

        // The normalization result.
        Authority.ProcessResult res = new Authority.ProcessResult();

        // Process the userinfo.
        processUserinfo(res, authority, charset);

        // Process the host.
        processHost(res, authority, charset);

        // Process the port.
        processPort(res, authority, normalizedScheme);

        // Build an Authority instance.
        return res.toAuthority();
    }


    private void processUserinfo(
        Authority.ProcessResult res, Authority authority, Charset charset)
    {
        res.userinfo = new UserinfoNormalizer().normalize(authority.getUserinfo(), charset);
    }


    private void processHost(
        Authority.ProcessResult res, Authority authority, Charset charset)
    {
        res.host = new HostNormalizer().normalize(authority.getHost(), charset);
    }


    private void processPort(
        Authority.ProcessResult res, Authority authority, String normalizedScheme)
    {
        res.port = new PortNormalizer().normalize(authority.getPort(), normalizedScheme);
    }
}
