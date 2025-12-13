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
 * <p>
 * Normalizes the {@code userinfo} component of a URI reference according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section 6:
 * Normalization and Comparison</a>.
 * </p>
 *
 * <p>Examples:</p>
 * <pre>{@code
 * // Parse a URI and normalize it.
 * URIReference normalized = URIReference
 *                               .parse("hTTp://example.com:80/a/b/c/../d/")
 *                               .normalize();
 *
 * System.out.println(normalized.isRelativeReference());     // false
 * System.out.println(normalized.getScheme());               // "http"
 * System.out.println(normalized.hasAuthority());            // true
 * System.out.println(normalized.getAuthority().toString()); // "example.com:80"
 * System.out.println(normalized.getUserinfo());             // null
 * System.out.println(normalized.getHost().getType());       // "REGNAME"
 * System.out.println(normalized.getHost().getValue());      // "example.com"
 * System.out.println(normalized.getPort());                 // -1
 * System.out.println(normalized.getPath());                 // "/a/b/d/"
 * System.out.println(normalized.getQuery());                // null
 * System.out.println(normalized.getFragment());             // null
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section 6:
 *      Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class UserinfoNormalizer extends PercentEncodedStringNormalizer
{
    /**
     * Normalizes a {@code userinfo} according to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
     * RFC 3986, Section 6: Normalization and Comparison</a>.
     *
     * @param userinfo
     *         A {@code userinfo} to normalize.
     *
     * @param charset
     *         The charset used for the path. Expected to be not {@code null}.
     *
     * @return
     *         A string value representing the normalized {@code userinfo}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     *      Section 6: Normalization and Comparison</a>
     */
    String normalize(String userinfo, Charset charset)
    {
        if (userinfo == null || userinfo.isEmpty())
        {
            return userinfo;
        }

        return process(userinfo, charset, new StringBuilder());
    }


    @Override
    protected boolean toLowerCase()
    {
        return false;
    }
}
