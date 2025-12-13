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


import static org.czeal.rfc3986.URIReference.ProcessResult;
import static org.czeal.rfc3986.Utils.newIAE;
import static org.czeal.rfc3986.Utils.newNPE;
import java.nio.charset.Charset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Parses a given string as a URI reference according to <a href="https://www.rfc-editor.org/rfc/rfc3986">
 * RFC 3986</a> and creates a {@link URIReference} instance, representing either
 * a URI or a relative reference.
 *
 * <p>Examples:</p>
 * <pre>{@code
 * // Parse a URI.
 * URIReference uriRef = new URIReferenceParser().parse("http://example.com/a");
 *
 * System.out.println(uriRef.isRelativeReference());     // false
 * System.out.println(uriRef.getScheme());               // "http"
 * System.out.println(uriRef.hasAuthority());            // true
 * System.out.println(uriRef.getAuthority().toString()); // "example.com"
 * System.out.println(uriRef.getUserinfo());             // null
 * System.out.println(uriRef.getHost().getType());       // "REGNAME"
 * System.out.println(uriRef.getHost().getValue());      // "example.com"
 * System.out.println(uriRef.getPort());                 // -1
 * System.out.println(uriRef.getPath());                 // "/a"
 * System.out.println(uriRef.getQuery());                // null
 * System.out.println(uriRef.getFragment());             // null
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 - Uniform Resource
 *      Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
class URIReferenceParser
{
    /**
     * Inner class representing the result of the URI reference parsing process.
     * This class holds intermediate values of the URI components during the parse
     * process.
     */
    private static class ParseResult extends ProcessResult
    {
        Matcher matcher;
    }


    /**
     * The pattern for parsing the five components of a URI, according to "RFC
     * 3986, Appendix B. Parsing a URI Reference with a Regular Expression".
     */
    private static final Pattern PATTERN_URI = Pattern.compile(
        "(?<scheme>[^:/?#]+):(\\/\\/(?<authority>[^/?#]*))?(?<path>[^?#]*)(\\?(?<query>[^#]*))?(#(?<fragment>.*))?");


    /**
     * The pattern for parsing the five components of a relative reference, according
     * to "RFC 3986, Appendix B. Parsing a URI Reference with a Regular Expression".
     */
    private static final Pattern PATTERN_REGEX_RELATIVE_REFERENCE = Pattern.compile(
        "(\\/\\/(?<authority>[^/?#]*))?(?<path>[^?#]*)(\\?(?<query>[^#]*))?(#(?<fragment>.*))?");


    /**
     * Parses the input string as a <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.1">
     * URI reference</a> based on <a href="https://www.rfc-editor.org/rfc/rfc3986">
     * RFC 3986</a>.
     *
     * <p>
     * The {@code uriRef} value must be a string representing a <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3">
     * URI</a> or <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">
     * relative reference</a>. If the {@code uriRef} value is invalid as a URI reference,
     * an {@code InvalidArgumentException} will be thrown.
     * </p>
     *
     * @param uriRef
     *         Required. The input string to parse as a URI reference.
     *
     * @param charset
     *         Required. The charset used in the input string.
     *
     * @return
     *         The URI reference obtained by parsing the input string.
     *
     * @throws NullPointerException
     *          If {@code uriRef} or {@code charset} is {@code null}.
     *
     * @throws IllegalArgumentException
     *          If the value of {@code uriRef} is invalid as a URI reference.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">RFC 3986
     *      Uniform Resource Identifier (URI): Generic Syntax</a>
     */
    URIReference parse(String uriRef, Charset charset)
    {
        // Validate the arguments.
        validate(uriRef, charset);

        // The parse result.
        ParseResult res = new ParseResult();

        // Set the charset.
        res.charset = charset;

        // Match the input string as a URI reference.
        processInput(res, uriRef);

        // Process the authority.
        processAuthority(res);

        // Process the path.
        processPath(res);

        // Process the query.
        processQuery(res);

        // Process the fragment.
        processFragment(res);

        // Build a URI reference instance.
        return res.toURIReference();
    }


    private void validate(String uriRef, Charset charset)
    {
        // Ensure the input string is not null.
        if (uriRef == null)
        {
            throw newNPE("The input string must not be null.");
        }

        // Ensure the charset is not null.
        if (charset == null)
        {
            throw newNPE("The charset must not be null.");
        }
    }


    private void processInput(ParseResult res, String uriRef)
    {
        // 4.1.  URI Reference
        //
        //   A URI-reference is either a URI or a relative reference.
        //   If the URI-reference's prefix does not match the syntax of a scheme
        //   followed by its colon separator, then the URI-reference is a relative
        //   reference.

        // Get a matcher to match the input string as a URI.
        Matcher matcher = PATTERN_URI.matcher(uriRef);

        // If the input string  matches the URI pattern.
        if (matcher.matches())
        {
            // The raw scheme.
            String scheme = matcher.group("scheme");

            // If the raw scheme is valid.
            if (isSchemeValid(scheme))
            {
                // The input string  starts with a valid scheme. Then, we can consider
                // the input string  as a URI.
                res.matcher           = matcher;
                res.scheme            = scheme;
                res.relativeReference = false;
                return;
            }
        }

        // We reach here if the input string  doesn't start with a valid scheme followed
        // by a colon. In this case, we consider the input string  as a relative reference.
        matchAsRelativeReference(res, uriRef);
    }


    private boolean isSchemeValid(String scheme)
    {
        try
        {
            // Validate the scheme.
            new SchemeValidator().validate(scheme);
        }
        catch (IllegalArgumentException e)
        {
            // The input string starts with a string followed by a colon but it is
            // invalid as a scheme. Then, we consider the input string  as a relative
            // reference.
            return false;
        }

        // The scheme value is valid.
        return true;
    }


    private void matchAsRelativeReference(ParseResult res, String uriRef)
    {
        // Get a matcher to match the input string as a relative reference.
        Matcher matcher = PATTERN_REGEX_RELATIVE_REFERENCE.matcher(uriRef);

        // If the input string doesn't match the relative reference pattern.
        if (!matcher.matches())
        {
            // The input string is invalid as a relative reference.
            throw newIAE(
                "The input string \"%s\" is invalid as a relative reference.", uriRef);
        }

        // OK. The input string is a valid relative reference.
        res.matcher           = matcher;
        res.relativeReference = true;
    }


    private void processAuthority(ParseResult res)
    {
        // The raw authority.
        String authority = res.matcher.group("authority");

        // Parse the raw authority as an Authority instance.
        res.authority = Authority.parse(authority, res.charset);
    }


    private void processPath(ParseResult res)
    {
        // The raw path.
        String path = res.matcher.group("path");

        // Validate the raw path.
        new PathValidator().validate(
            path, res.charset, res.relativeReference, res.authority != null);

        // Set it to the result.
        res.path = path;
    }


    private void processQuery(ParseResult res)
    {
        // The raw query.
        String query = res.matcher.group("query");

        // Validate the raw query.
        new QueryValidator().validate(query, res.charset);

        // Set it to the result.
        res.query = query;
    }


    private void processFragment(ParseResult res)
    {
        // The raw fragment.
        String fragment = res.matcher.group("fragment");

        // Validate the raw fragment.
        new FragmentValidator().validate(fragment, res.charset);

        // Set it to the result.
        res.fragment = fragment;
    }
}
