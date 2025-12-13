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
 * Normalizes the {@code query} component of a URI reference according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986, Section 6:
 * Normalization and Comparison</a>.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class QueryNormalizer extends PercentEncodedStringNormalizer
{
    /**
     * Normalizes a {@code query} according to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
     * RFC 3986, Section 6: Normalization and Comparison</a>.
     *
     * @param query
     *         A path to normalize.
     *
     * @param charset
     *         The charset used for the path. Expected to be not {@code null}.
     *
     * @return
     *         A string value representing the normalized query.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
     *      Section 6: Normalization and Comparison</a>
     */
    String normalize(String query, Charset charset)
    {
        if (query == null)
        {
            return null;
        }

        // Normalize the query string.
        return process(query, charset, new StringBuilder());
    }


    @Override
    protected boolean toLowerCase()
    {
        return false;
    }
}
