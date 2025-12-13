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


import static org.czeal.rfc3986.Utils.isDigit;
import static org.czeal.rfc3986.Utils.newIAE;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates the {@code port} component of a URI reference according to the syntax
 * defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 * Appendix A. Collected ABNF for URI</a> as follows.
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * port = *DIGIT
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class PortValidator
{
    /**
     * Validates a value as a port.
     *
     * @param port
     *         A port value.
     *
     * @throws IllegalArgumentException
     *         If the {@code port} value is invalid.
     */
    void validate(String port)
    {
        if (port == null)
        {
            // If the port value is null, it means the input string doesn't
            // contain a port.
            return;
        }

        if (port.isEmpty())
        {
            // If the port value is empty, it means the input string contains
            // a colon (":") delimiter for the port value but the port value is
            // empty.
            return;
        }

        for (int i = 0; i < port.length(); i++)
        {
            char c = port.charAt(i);

            if (!isDigit(c))
            {
                throw newIAE(
                    "The port value \"%s\" has an invalid character \"%s\" at the " +
                    "index %d.", port, c, i);
            }
        }
    }


    /**
     * Validates a value as a port.
     *
     * @param port
     *         A port value.
     *
     * @throws IllegalArgumentException
     *         If the {@code port} value is invalid.
     */
    void validate(int port)
    {
        if (port == -1)
        {
            // -1 is the default value.
            return;
        }

        if (port < 0)
        {
            throw newIAE("The port value \"%d\" is negative.", port);
        }
    }
}
