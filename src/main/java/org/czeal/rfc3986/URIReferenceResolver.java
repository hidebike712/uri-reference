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
import static org.czeal.rfc3986.Utils.dropLastSegment;
import static org.czeal.rfc3986.Utils.newNPE;
import static org.czeal.rfc3986.Utils.newIAE;
import static org.czeal.rfc3986.Utils.newISE;
import static org.czeal.rfc3986.Utils.removeDotSegments;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Resolves a URI reference against a base URI according to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-5">
 * RFC 3986, Section 5: Reference Resolution</a>.
 *
 * <p>Examples:</p>
 * <pre>{@code
 * // Parse a relative reference.
 * URIReference relRef = URIReference.parse("/a/b");
 *
 * // Parse a base URI.
 * URIReference baseUri = URIReference.parse("http://example.com");
 *
 * // Resolve the relative reference against the base URI.
 * URIReference resolved = new URIReferenceResolver(relRef, baseUri);
 *
 * System.out.println(resolved.isRelativeReference());     // false
 * System.out.println(resolved.getScheme());               // "http"
 * System.out.println(resolved.hasAuthority());            // true
 * System.out.println(resolved.getAuthority().toString()); // "example.com"
 * System.out.println(resolved.getUserinfo());             // null
 * System.out.println(resolved.getHost().getType());       // "REGNAME"
 * System.out.println(resolved.getHost().getValue());      // "example.com"
 * System.out.println(resolved.getPort());                 // -1
 * System.out.println(resolved.getPath());                 // "/a/b"
 * System.out.println(resolved.getQuery());                // null
 * System.out.println(resolved.getFragment());             // null
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-5">RFC 3986, Section 5:
 *      Reference Resolution</a>
 *
 * @author Hideki Ikeda
 */
class URIReferenceResolver
{
    /**
     * Merges a relative-path reference with the path of a base URI according to
     * <a href="https://www.rfc-editor.org/rfc/rfc3986#section-5.2.3">RFC 3986,
     * 5.2.3. Merge Paths</a>.
     *
     * @param uriRefPath
     *         The path of a URI reference to merge
     *
     * @param basePath
     *         The path of a base URI to merge the
     *
     * @param hasAuthority
     *         Whether the base URI has an authority or not.
     *
     * @return The merged path.
     */
    private static String mergePath(
        String uriRefPath, String basePath, boolean hasAuthority)
    {
        // NOTE:
        //     uriRefPath.length() > 0
        //     uriRefPath.startsWith("/") != false

        if (hasAuthority && basePath.isEmpty())
        {
            return "/".concat(uriRefPath);
        }
        else
        {
            return dropLastSegment(basePath, false).concat(uriRefPath);
        }
    }


    /**
     * Resolves a URI reference against a base URI.
     *
     * @param uriRef
     *         A URI reference to resolve against the value of {@code baseUriRef}.
     *
     * @param baseUriRef
     *         A base URI against which the value of {@code uriRef} is resolved.
     *
     * @return The URI reference obtained by resolving {@code uriRef} against
     *         {@code baseUriRef}.
     *
     * @throws NullPointerException
     *         If {@code uriRef} or {@code baseUriRef} is {@code null}.
     *
     * @throws IllegalStateException
     *         If this URI reference is not an absolute URI.
     */
    URIReference resolve(URIReference uriRef, URIReference baseUriRef)
    {
        // Validate the arguments.
        validate(uriRef, baseUriRef);

        // The resolution result.
        ProcessResult res = new ProcessResult();

        // Set the charset.
        res.charset = uriRef.getCharset();

        // The resolved URI reference is always a URI.
        res.relativeReference = false;

        // Resolve the URI Reference against the base URI.
        process(res, uriRef, baseUriRef);

        // Return the result.
        return res.toURIReference();
    }


    private void validate(URIReference uriRef, URIReference baseUriRef)
    {
        // Ensure the URI reference to be resolved is not null.
        if (uriRef == null)
        {
            throw newNPE("The URI reference to be resolved must not be null.");
        }

        // Ensure the base URI is not null.
        if (baseUriRef == null)
        {
            throw newNPE("The base URI reference must not be null.");
        }

        // Check the charset of both URI reference.
        if (uriRef.getCharset() != baseUriRef.getCharset())
        {
            throw newIAE(
                "The charset of the target URI reference doesn't match the charset of the base URI.");
        }

        // Ensure this URI reference can be used as a base URI.
        //
        // RFC 3986, 5.1. Establishing a Base URI
        //
        //   A base URI must conform to the <absolute-URI> syntax rule
        //   (Section 4.3). If the base URI is obtained from a URI reference,
        //   then that reference must be converted to absolute form and
        //   stripped of any fragment component prior to its use as a
        //   base URI.
        //
        // RFC 3986, 4.3.  Absolute URI
        //
        //   Some protocol elements allow only the absolute form of a URI without
        //   a fragment identifier.  For example, defining a base URI for later
        //   use by relative references calls for an absolute-URI syntax rule that
        //   does not allow a fragment.
        //
        //     absolute-URI  = scheme ":" hier-part [ "?" query ]

        if (baseUriRef.getScheme() == null)
        {
            throw newISE("The base URI must have a scheme.");
        }

        if (baseUriRef.getFragment() != null)
        {
            throw newISE("The base URI must not have a fragment.");
        }
    }


    private void process(
        ProcessResult res, URIReference uriRef, URIReference baseUriRef)
    {
        if (uriRef.getScheme() != null)
        {
            processOnNonNullScheme(res, uriRef);
        }
        else
        {
            processOnNullScheme(res, uriRef, baseUriRef);
        }

        res.fragment = uriRef.getFragment();
    }


    private void processOnNonNullScheme(ProcessResult res, URIReference uriRef)
    {
        res.scheme    = uriRef.getScheme();
        res.authority = uriRef.getAuthority();
        res.path      = removeDotSegments(uriRef.getPath());
        res.query     = uriRef.getQuery();
    }


    private void processOnNullScheme(
        ProcessResult res, URIReference uriRef, URIReference baseUriRef)
    {
        if (uriRef.getAuthority() != null)
        {
            processOnNonNullAuthority(res, uriRef, baseUriRef);
        }
        else
        {
            processOnNullAuthority(res, uriRef, baseUriRef);
        }

        res.scheme = baseUriRef.getScheme();
    }


    private void processOnNonNullAuthority(
        ProcessResult res, URIReference uriRef, URIReference baseUriRef)
    {
        res.authority = uriRef.getAuthority();
        res.path      = removeDotSegments(uriRef.getPath());
        res.query     = uriRef.getQuery();
    }


    private void processOnNullAuthority(
        ProcessResult res, URIReference uriRef, URIReference baseUriRef)
    {
        if (!uriRef.getPath().isEmpty())
        {
            processOnNonNullPath(res, uriRef, baseUriRef);
        }
        else
        {
            processOnNullPath(res, uriRef, baseUriRef);
        }

        res.authority = baseUriRef.getAuthority();
    }


    private void processOnNonNullPath(
        ProcessResult res, URIReference uriRef, URIReference baseUriRef)
    {
        if (uriRef.getPath().startsWith("/"))
        {
            res.path = removeDotSegments(uriRef.getPath());
        }
        else
        {
            res.path = removeDotSegments(mergePath(
                uriRef.getPath(), baseUriRef.getPath(), baseUriRef.hasAuthority()));
        }

        res.query = uriRef.getQuery();
    }


    private void processOnNullPath(
        ProcessResult res, URIReference uriRef, URIReference baseUriRef)
    {
        res.path = baseUriRef.getPath();

        if (uriRef.getQuery() != null)
        {
            res.query = uriRef.getQuery();
        }
        else
        {
            res.query = baseUriRef.getQuery();
        }
    }
}
