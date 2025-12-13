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
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Parses a given string as the {@code authority} component of a URI reference,
 * according to <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>. If
 * parsing succeeds, it creates an {@link Authority} object. If parsing fails due
 * to invalid input string, it throws an {@code IllegalArgumentException}.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 - Uniform Resource
 *      Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
class AuthorityParser
{
    /**
     * Inner class representing the result of the Authority building process.
     * This class holds intermediate values of the Authority components during the
     * parse process.
     */
    private static class ParseResult extends Authority.ProcessResult
    {
        Matcher matcher;
    }


    /**
     * The regular expression for parsing an authority.
     */
    private static final Pattern PATTERN_AUTHORITY = Pattern.compile(
        "((?<userinfo>[^@]*)@)?(?<host>(\\[[^]]*\\])|[^:]*)?(:(?<port>.*))?");


    /**
     * Parses a given string as the {@code authority} component of a URI reference,
     * according to <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986</a>
     * If parsing succeeds, this method creates an {@link Authority} instance. If
     * parsing fails due to invalid input string, it throws an {@code IllegalArgumentException}.
     *
     * @param authority
     *         The input string to parse as the {@code authority} component of a
     *         URI reference.
     *
     * @param charset
     *         The charset used for percent-encoding some characters (e.g. reserved
     *         characters) contained in the {@code authority} parameter.
     *
     * @return
     *         The {@code Authority} object representing the parsed {@code authority}
     *         component.
     *
     * @throws NullPointerException
     *          If the value of the {@code authority} parameter or the {@code charset}
     *          parameter is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the value of the {@code authority} parameter is invalid as the
     *          {@code authority} of a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">
     *      RFC 3986 Uniform Resource Identifier (URI): Generic Syntax</a>
     */
    Authority parse(String authority, Charset charset)
    {
        if (authority == null)
        {
            // The input string doesn't contain an authority.
            return null;
        }

        // The parse result.
        ParseResult res = new ParseResult();

        // Process the authority.
        processAuthority(res, authority);

        // Process the userinfo.
        processUserinfo(res, charset);

        // Process the host.
        processHost(res, charset);

        // Process the port.
        processPort(res);

        // Return the parser result.
        return res.toAuthority();
    }


    private void processAuthority(ParseResult res, String authority)
    {
        // Get a matcher to match the input string as an authority.
        Matcher matcher = PATTERN_AUTHORITY.matcher(authority);

        // Match the input string as an authority..
        if (!matcher.matches())
        {
            // The input string is invalid as an authority.
            throw newIAE("The input \"%s\" is invalid as an authority.", authority);
        }

        // Set the matcher.
        res.matcher = matcher;
    }


    private void processUserinfo(ParseResult res, Charset charset)
    {
        // The raw userinfo.
        String rawUserinfo = res.matcher.group("userinfo");

        // Validate the raw userinfo.
        new UserinfoValidator().validate(rawUserinfo, charset);

        // Set it to the result.
        res.userinfo = rawUserinfo;
    }


    private void processHost(ParseResult res, Charset charset)
    {
        // The raw host.
        String rawHost = res.matcher.group("host");

        // Parse the raw host value into a Host instance.
        res.host = Host.parse(rawHost, charset);
    }


    private void processPort(ParseResult res)
    {
        // The raw port.
        String rawPort = res.matcher.group("port");

        // Validate the raw port.
        new PortValidator().validate(rawPort);

        // Parse the raw port into an int value.
        res.port = parsePort(rawPort);
    }


    private int parsePort(String rawPort)
    {
        if (rawPort == null || rawPort.isEmpty())
        {
            // If the "rawPort" value is null, it means the URI reference doesn't
            // contain a port. If it is empty, it means the input string contains
            // a colon (":") delimiter for the port value but the port value is
            // empty. In these cases, the value of the parsed authority component
            // is set to -1 (the default value).
            return -1;
        }

        try
        {
            // Parse the extracted port value into an int value and set it as the
            // value of "newAuthority.port".
            return Integer.parseInt(rawPort);
        }
        catch (NumberFormatException e)
        {
            // The number in the port is invalid.
            // NOTE: We will reach this point if, for instance, the number is too
            // large as an int value.
            throw newIAE("The port value \"%s\" is invalid as a number.", rawPort);
        }
    }
}
