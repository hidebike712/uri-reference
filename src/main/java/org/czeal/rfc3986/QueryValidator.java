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


import static org.czeal.rfc3986.Utils.isSubdelim;
import static org.czeal.rfc3986.Utils.isUnreserved;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Validates {@code query} of a URI reference according to the following syntax
 * defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 * Appendix A. Collected ABNF for URI</a>.
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * query = *( pchar / "/" / "?" )
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class QueryValidator extends PercentEncodedStringValidator
{
    QueryValidator()
    {
        super("query");
    }


    /**
     * Validates a value as a query.
     *
     * @param query
     *         A query value.
     *
     * @param charset
     *         The charset used for the query value.
     *
     * @throws IllegalArgumentException
     *         If the query value is invalid.
     */
    void validate(String query, Charset charset)
    {
        if (query == null || query.isEmpty())
        {
            return;
        }

        process(query, charset, null);
    }


    @Override
    protected boolean isValidOnNonPercent(char c)
    {
        return isUnreserved(c) ||
               isSubdelim(c)   ||
               c == ':'        ||
               c == '@'        ||
               c == '/'        ||
               c == '?';
    }
}
