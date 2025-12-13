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


import static org.czeal.rfc3986.Utils.isAlphabet;
import static org.czeal.rfc3986.Utils.isDigit;
import static org.czeal.rfc3986.Utils.newIAE;
import static org.czeal.rfc3986.Utils.newNPE;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Validates the {@code scheme} component of a URI reference, according to the
 * syntax defined in <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">
 * RFC 3986, Appendix A. Collected ABNF for URI</a> as follows.
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class SchemeValidator
{
    /**
     * Validates a scheme value.
     *
     * @param scheme
     *         A scheme value.
     *
     * @throws IllegalArgumentException
     *         If the scheme value is invalid.
     */
    void validate(String scheme)
    {
        // If the scheme is null.
        if (scheme == null)
        {
            // The scheme must not be empty.
            throw newNPE("The scheme value must not be null.");
        }

        // If the scheme is empty.
        if (scheme.isEmpty())
        {
            // The scheme must not be empty.
            throw newIAE("The scheme value must not be empty.");
        }

        // Validate the first character in the scheme.
        validateFirstCharacter(scheme);

        // Check the remaining characters in the scheme.
        validateRemainingCharacters(scheme);
    }


    private void validateFirstCharacter(String scheme)
    {
        char c = scheme.charAt(0);

        if (!isAlphabet(c))
        {
            throw newIAE(
                "The scheme value \"%s\" has an invalid character \"%s\" at " +
                "the index 0.", scheme, c);
        }
    }


    private void validateRemainingCharacters(String scheme)
    {
        for (int i = 1; i < scheme.length(); i++)
        {
            char c = scheme.charAt(i);

            if (!isValid(c))
            {
                throw newIAE(
                    "The scheme value \"%s\" has an invalid character \"%s\" at " +
                    "the index %d.", scheme, c, i);
            }
        }
    }


    private boolean isValid(char c)
    {
        return isAlphabet(c) ||
               isDigit(c)    ||
               c == '+'      ||
               c == '-'      ||
               c == '.';
    }
}
