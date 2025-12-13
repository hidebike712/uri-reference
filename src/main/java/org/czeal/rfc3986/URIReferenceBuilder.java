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


import static java.nio.charset.StandardCharsets.UTF_8;
import static org.czeal.rfc3986.Utils.newNPE;
import java.nio.charset.Charset;
import java.util.Optional;
import org.czeal.rfc3986.URIReference.ProcessResult;


/**
 * A builder class for constructing URI references.
 *
 * <p>
 * This class provides a fluent API to build a {@link URIReference} object incrementally
 * by setting its various components such as {@code scheme}, {@code userinfo},
 * {@code host}, {@code port}, {@code path}, {@code query}, and {@code fragment}.
 * </p>
 *
 * <p>
 * This builder supports both absolute and relative URI references.
 * </p>
 *
 * <p>Examples:</p>
 * <pre>{@code
 * //---------------------------------------------------------------------------
 * // Build a URI reference.
 * //---------------------------------------------------------------------------
 * URIReference uriRef = new URIReferenceBuilder()
 *                           .setScheme("http")
 *                           .setHost("example.com")
 *                           .setPath("/a/b/c")
 *                           .query("k1", "v1")
 *                           .build();
 *
 * System.out.println(uriRef.toString());                          // "http://example.com/a/b/c?k1=v1"
 * System.out.println(uriRef.getScheme());                         // "http"
 * System.out.println(uriRef.getAuthority());                      // "example.com"
 * System.out.println(uriRef.getUserinfo());                       // null
 * System.out.println(uriRef.getAuthority().getHost().getType());  // "REGNAME"
 * System.out.println(uriRef.getAuthority().getHost().getValue()); // "example.com"
 * System.out.println(uriRef.getPort());                           // -1
 * System.out.println(uriRef.getPath());                           // "/a/b/c"
 * System.out.println(uriRef.getQuery());                          // "k1=v1"
 * System.out.println(uriRef.getFragment());                       // null
 *
 *
 * //---------------------------------------------------------------------------
 * // Build a URI reference from another URI reference.
 * //---------------------------------------------------------------------------
 * URIReference uriRef = URIReferenceBuilder
 *                           .fromURIReference("http://example.com/a/b/c?k1=v1")
 *                           .appendPath("d", "e", "f")
 *                           .appendQueryParam("k2", "v2")
 *                           .build();
 *
 * System.out.println(uriRef.toString());                          // "http://example.com/a/b/c/d/e/f?k1=v1&k2=v2"
 * System.out.println(uriRef.getScheme());                         // "http"
 * System.out.println(uriRef.getAuthority().toString());           // "example.com"
 * System.out.println(uriRef.getUserinfo());                       // null
 * System.out.println(uriRef.getAuthority().getHost().getType());  // "REGNAME"
 * System.out.println(uriRef.getAuthority().getHost().getValue()); // "example.com"
 * System.out.println(uriRef.getPort());                           // -1
 * System.out.println(uriRef.getPath());                           // "/a/b/c/d/e/f"
 * System.out.println(uriRef.getQuery());                          // "k1=v1&k2=&v2"
 * System.out.println(uriRef.getFragment());                       // null
 *
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986">RFC 3986 - Uniform Resource
 *      Identifier (URI): Generic Syntax</a>
 *
 * @author Hideki Ikeda
 */
public class URIReferenceBuilder
{
    /**
     * Creates a {@link URIReferenceBuilder} instance with a given string representing
     * a URI reference. This method copies the following information to the created
     * instance:
     *
     * <ul>
     * <li>charset</li>
     * <li>scheme</li>
     * <li>userinfo</li>
     * <li>host</li>
     * <li>port</li>
     * <li>query</li>
     * <li>fragment</li>
     * </ul>
     *
     * <p>
     * Note that this method works as if invoking it were equivalent to evaluating
     * the following expression:
     * </p>
     *
     * <pre>
     * <code>{@link #fromURIReference(URIReference) fromURIReference}({@link
     * URIReference}.{@link URIReference#parse(String) parse}(uriRef))</code>
     * </pre>
     *
     * @param uriRef
     *         A string representing a URI reference.
     *
     * @return
     *         A {@link URIReferenceBuilder} instance initialized with the given
     *         URI reference information.
     */
    public static URIReferenceBuilder fromURIReference(String uriRef)
    {
        return fromURIReference(URIReference.parse(uriRef));
    }


    /**
     * Creates a {@link URIReferenceBuilder} instance with a given string representing
     * a URI reference. This method copies the following information to the created
     * instance:
     *
     * <ul>
     * <li>charset</li>
     * <li>scheme</li>
     * <li>userinfo</li>
     * <li>host</li>
     * <li>port</li>
     * <li>query</li>
     * <li>fragment</li>
     * </ul>
     *
     * <p>
     * Note that this method works as if invoking it were equivalent to evaluating
     * the following expression:
     * </p>
     *
     * <pre>
     * <code>new URIReferenceBuilder().{@link #uriRef(URIReference) uriRef}(uriRef)</code>
     * </pre>
     *
     * @param uriRef
     *         A {@link URIReference} instance.
     *
     * @return
     *         A {@link URIReferenceBuilder} instance initialized with the given
     *         URI reference information.
     */
    public static URIReferenceBuilder fromURIReference(URIReference uriRef)
    {
        return new URIReferenceBuilder().uriRef(uriRef);
    }


    /**
     * The charset for percent-encoding characters (e.g. reserved characters) in
     * the resultant URI reference.
     */
    private Charset charset;


    /**
     * The scheme of the resultant URI reference.
     */
    private String scheme;


    /**
     * The userinfo of the resultant URI reference.
     */
    private String userinfo;


    /**
     * The host of the resultant URI reference.
     */
    private String host;


    /**
     * The port of the resultant URI reference.
     */
    private int port = -1;


    /**
     * The path segments of the resultant URI reference.
     */
    private PathSegments pathSegments;


    /**
     * The query parameters of the resultant URI reference.
     */
    private QueryParams queryParams;


    /**
     * The fragment of the resultant URI reference.
     */
    private String fragment;


    /**
     * Whether the authority is required for the resultant URI reference or not.
     */
    private boolean authorityRequired = true;


    /**
     * Sets information about a given {@link URIReferenceBuilder} instance. Specifically,
     * it copies the following information from the given {@code URIReferenceBuilder}
     * instance to this instance.
     *
     * <ul>
     * <li>charset</li>
     * <li>scheme</li>
     * <li>userinfo</li>
     * <li>host</li>
     * <li>port</li>
     * <li>query</li>
     * <li>fragment</li>
     * </ul>
     *
     * @param uriRef
     *         A {@link URIReference} instance.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder uriRef(URIReference uriRef)
    {
        if (uriRef == null)
        {
            throw newNPE("The URI reference must not be null.");
        }

        charset      = uriRef.getCharset();
        scheme       = uriRef.getScheme();
        userinfo     = uriRef.getUserinfo();
        host         = Optional.ofNullable(uriRef.getHost()).map(Host::getValue).orElse(null);
        port         = uriRef.getPort();
        pathSegments = PathSegments.parse(uriRef.getPath());
        queryParams  = QueryParams.parse(uriRef.getQuery());
        fragment     = uriRef.getFragment();

        return this;
    }


    /**
     * Sets the charset used in the resultant URI reference.
     *
     * <p>
     * This method replaces existing charset value with the given value.
     * </p>
     *
     * @param charset
     *         The charset.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setCharset(Charset charset)
    {
        this.charset = charset;

        return this;
    }


    /**
     * Sets the scheme.
     *
     * <p>
     * This method replaces existing {@code scheme} value with the given value.
     * </p>
     *
     * @param scheme
     *         The scheme of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the scheme.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setScheme(String scheme)
    {
        this.scheme = scheme;

        return this;
    }


    /**
     * Sets the userinfo.
     *
     * <p>
     * This method replaces existing {@code userinfo} value with the given value.
     * </p>
     *
     * @param userinfo
     *         The userinfo of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the userinfo.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setUserinfo(String userinfo)
    {
        this.userinfo = userinfo;

        return this;
    }


    /**
     * Sets the host.
     *
     * <p>
     * This method replaces existing {@code host} value with the given value.
     * </p>
     *
     * @param host
     *         The host of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the host.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setHost(String host)
    {
        this.host = host;

        return this;
    }


    /**
     * Sets the port.
     *
     * <p>
     * This method replaces existing {@code port} value with the given value.
     * </p>
     *
     * @param port
     *         The port of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the port.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setPort(int port)
    {
        this.port = port;

        return this;
    }


    /**
     * Sets the path.
     *
     * <p>
     * This method replaces existing {@code path} value with the given value.
     * </p>
     *
     * @param path
     *         The path of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the path.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setPath(String path)
    {
        this.pathSegments = PathSegments.parse(path);

        return this;
    }


    /**
     * Sets the query.
     *
     * <p>
     * This method replaces the existing {@code query} value with the given value.
     * </p>
     *
     * @param query
     *         The query of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the query.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setQuery(String query)
    {
        this.queryParams = QueryParams.parse(query);

        return this;
    }


    /**
     * Sets the fragment.
     *
     * <p>
     * This method replaces existing {@code fragment} value with the given value.
     * </p>
     *
     * @param fragment
     *         The fragment of the resultant URI reference. Specifying {@code null}
     *         for this property unsets the fragment.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setFragment(String fragment)
    {
        this.fragment = fragment;

        return this;
    }


    /**
     * Determines whether or not the authority is required in the resultant URI
     * reference.
     *
     * @param authorityRequired
     *         If {@code true}, the authority part is present in the resultant URI
     *         reference; otherwise, it will be omitted.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder setAuthorityRequired(boolean authorityRequired)
    {
        this.authorityRequired = authorityRequired;

        return this;
    }


    /**
     * Appends a new query parameter to the resultant URI reference.
     *
     * @param key
     *         The key of the new query parameter.
     *
     * @param value
     *         The value of the new query parameter.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder appendQueryParam(String key, String value)
    {
        if (queryParams == null)
        {
            queryParams = new QueryParams();
        }

        queryParams.add(key, value);

        return this;
    }


    /**
     * Replaces the value(s) of the query parameter(s) specified by the key with
     * a new value.
     *
     * @param key
     *         The key of the query parameter(s) whose value(s) is to be replaced.
     *
     * @param value
     *         A new value of the new query parameter.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder replaceQueryParam(String key, String value)
    {
        if (queryParams != null)
        {
            queryParams.replace(key, value);
        }

        return this;
    }


    /**
     * Removes the query parameter(s) specified by a key.
     *
     * @param key
     *         The key of the query parameter(s) to be removed.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder removeQueryParam(String key)
    {
        if (queryParams != null)
        {
            queryParams.remove(key);
        }

        return this;
    }


    /**
     * Appends a path segment.
     *
     * @param segment
     *         A path segment.
     *
     * @return
     *         {@code this} object.
     */
    public URIReferenceBuilder appendPathSegments(String... segment)
    {
        if (pathSegments == null)
        {
            pathSegments = new PathSegments();
        }

        pathSegments = pathSegments.add(segment);

        return this;
    }


    /**
     * Builds a URI reference.
     *
     * @return
     *         An {@link URIReference} object representing the resultant URI reference.
     */
    public URIReference build()
    {
        // The resultant URI reference.
        ProcessResult res = new ProcessResult();

        // Process the charset.
        processCharset(res);

        // Process the scheme.
        processScheme(res);

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


    private void processCharset(ProcessResult res)
    {
        // Set the charset.
        res.charset = charset != null ? charset : UTF_8;
    }


    private void processScheme(ProcessResult res)
    {
        if (scheme != null)
        {
            // Validate the scheme value.
            new SchemeValidator().validate(scheme);

            // Set the scheme.
            res.scheme = scheme;

            // The URI reference is a URI.
            res.relativeReference = false;
        }
        else
        {
            // The URI reference is a relative reference.
            res.relativeReference = true;
        }
    }


    private void processAuthority(ProcessResult res)
    {
        // If the authority is not required.
        if (!authorityRequired)
        {
            return;
        }

        // Create an authority.
        res.authority = new AuthorityBuilder()
                            .setCharset(charset)
                            .setUserinfo(userinfo)
                            .setHost(host)
                            .setPort(port)
                            .build();
    }


    private void processPath(ProcessResult res)
    {
        // Convert the path segments to a string.
        String path = pathSegments == null ? null : pathSegments.toString();

        // Validate the path.
        new PathValidator().validate(
            path, res.charset, res.relativeReference, res.authority != null);

        // Set the path.
        res.path = path;
    }


    private void processQuery(ProcessResult res)
    {
        // Convert the query parameters to a string.
        String query = (queryParams == null || queryParams.isEmpty()) ? null : queryParams.toString();

        // Validate the query.
        new QueryValidator().validate(query, res.charset);

        // Set the query.
        res.query = query;
    }


    private void processFragment(ProcessResult res)
    {
        // Validate the fragment.
        new FragmentValidator().validate(fragment, res.charset);

        // Set the fragment.
        res.fragment = fragment;
    }
}
