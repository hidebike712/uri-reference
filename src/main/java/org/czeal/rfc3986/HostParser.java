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
import java.nio.charset.StandardCharsets;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Parses a given string as the {@code host} of a URI reference, according to
 * <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If parsing
 * succeeds, this method creates a {@link Host} object. If parsing fails due to
 * invalid input string, it throws an {@code IllegalArgumentException}. Note that
 * this method works as if invoking it were equivalent to evaluating the expression
 * <code>{@link #parse(String, Charset) parse}(host, {@link StandardCharsets}.{@link
 * StandardCharsets#UTF_8 UTF_8})</code>.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 - Uniform Resource
 *      Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
class HostParser
{
    /**
     * Parses a string as an {@code host} component of a URI reference based on
     * <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a> and creates
     * a {@link Host} instance if parsing succeeds. If parsing fails due to invalid
     * input string, an {@code IllegalArgumentException} will be thrown.
     *
     * @param host
     *         Required. The input string for this parser to parse as an {@code
     *         host}.
     *
     * @param charset
     *         Required. The charset used in the {@code host}.
     *
     * @return
     *         The {@code Host} instance obtained by parsing the {@code host}
     *         value as an {@code host} component.
     *
     * @throws NullPointerException
     *          If {@code charset} is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the {@code host} value is invalid as an {@code host}.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">
     *      RFC 3986 Uniform Resource Identifier (URI): Generic Syntax</a>
     */
    Host parse(String host, Charset charset)
    {
        return new Host(new HostTypeDeterminer().determine(host, charset), host);
    }
}
