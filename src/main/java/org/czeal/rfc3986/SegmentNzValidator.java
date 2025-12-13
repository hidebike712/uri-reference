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


import static org.czeal.rfc3986.Utils.newIAE;
import static org.czeal.rfc3986.Utils.newNPE;
import java.nio.charset.Charset;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates a value as a {@code segment-nz} (non-zero-length path segment),
 * according to the following syntax defined in "RFC 3986, Appendix A. Collected
 * ABNF for URI".
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * segment-nz = 1*pchar
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986, Appendix A.
 *      Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class SegmentNzValidator extends SegmentValidator
{
    /**
     * Validates a value as a {@code segment-nz} (non-zero-length path segment).
     *
     * @param segment
     *         A {@code segment-nz} value.
     *
     * @param charset
     *         The charset used for the {@code segment-nz} value.
     *
     * @throws IllegalArgumentException
     *         If the {@code segment} value is invalid.
     */
    @Override
    void validate(String segment, Charset charset)
    {
        if (segment == null)
        {
            throw newNPE("The %s value must not be null.", name);
        }

        if (segment.isEmpty())
        {
            throw newIAE("The %s value must not be empty.", name);
        }

        process(segment, charset, null);
    }
}
