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
 * Validates the {@code userinfo} of a URI reference according to the following
 * syntax defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">
 * "RFC 3986, Appendix A. Collected ABNF for URI"</a>.
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class UserinfoValidator extends PercentEncodedStringValidator
{
    UserinfoValidator()
    {
        super("userinfo");
    }


    /**
     * Validates a value as a {@code userinfo}.
     *
     * @param userinfo
     *         A {@code userinfo} value.
     *
     * @param charset
     *         The charset used for the {@code userinfo} value.
     *
     * @throws IllegalArgumentException
     *         If the {@code userinfo} value is invalid.
     */
    void validate(String userinfo, Charset charset)
    {
        if (userinfo == null || userinfo.isEmpty())
        {
            return;
        }

        process(userinfo, charset, null);
    }


    @Override
    protected boolean isValidOnNonPercent(char c)
    {
        return isUnreserved(c) || isSubdelim(c) || c == ':';
    }
}
