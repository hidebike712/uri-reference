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
import static org.czeal.rfc3986.Utils.newISE;
import static org.czeal.rfc3986.Utils.newNPE;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * Normalizes a URI reference according to <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
 * RFC 3986, Section 6: Normalization and Comparison</a>.
 *
 * <p>Examples:</p>
 * <pre>{@code
 * // Normalize a URI reference.
 * URIReference normalized = new URIReferenceNormalizer()
 *                               .normalize("hTTp://example.com:80/a/b/c/../d/");
 *
 * System.out.println(uriRef.getScheme());                         // "http"
 * System.out.println(uriRef.getAuthority().getUserinfo());        // null
 * System.out.println(uriRef.getAuthority().getHost().getType());  // "REGNAME"
 * System.out.println(uriRef.getAuthority().getHost().getValue()); // "example.com"
 * System.out.println(uriRef.getAuthority().getPort());            // -1
 * System.out.println(uriRef.getPath());                           // "/a/b/d/"
 * System.out.println(uriRef.getQuery());                          // null
 * System.out.println(uriRef.getFragment());                       // null
 * }</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">RFC 3986,
 *      Section 6: Normalization and Comparison</a>
 *
 * @author Hideki Ikeda
 */
class URIReferenceNormalizer
{
    /**
     * Normalizes a URI reference <a href="https://www.rfc-editor.org/rfc/rfc3986#section-6">
     * RFC 3986, Section 6: Normalization and Comparison</a>.
     *
     * <p>
     * This method does not modify the state of the give {@link URIReference} instance.
     * Instead, it creates a new {@link URIReference} instance and initializes it
     * with the information about the normalized URI reference.
     * </p>
     *
     * <p>
     * Note that this method throws an {@code IllegalStateException} if the URI
     * reference specified by the {@code uriRef} argument has not been resolved
     * yet.
     * </p>
     *
     * @param uriRef
     *         The URI reference to normalize.
     *
     * @return
     *         A new {@code URIReference} instance representing the normalized
     *         URI reference.
     *
     * @throws IllegalStateException
     *         If the URI reference specified by the {@code uriRef} argument has
     *         not been resolved yet.
     */
    URIReference normalize(URIReference uriRef)
    {
        // Validate the URI reference.
        validate(uriRef);

        // The parse result.
        ProcessResult res = new ProcessResult();

        // Set the charset.
        res.charset = uriRef.getCharset();

        // The normalized URI reference is always a URI.
        res.relativeReference = false;

        // Process the scheme.
        processScheme(res, uriRef);

        // Process the authority.
        processAuthority(res, uriRef);

        // Process the path.
        processPath(res, uriRef);

        // Process the query.
        processQuery(res, uriRef);

        // Process the fragment.
        processFragment(res, uriRef);

        // Build a URI reference instance.
        return res.toURIReference();
    }


    private void validate(URIReference uriRef)
    {
        // Ensure the input URI reference is not null.
        if (uriRef == null)
        {
            throw newNPE("The URI reference must not be null.");
        }

        // Ensure the URI reference has been resolved according to the following
        // requirement.
        //
        //   RFC 3986, 5.2.1. Pre-parse the Base URI
        //
        //     A URI reference must be transformed to its target URI before
        //     it can be normalized.

        if (uriRef.isRelativeReference())
        {
            throw newISE("A relative references must be resolved before it can be normalized.");
        }
    }


    private void processScheme(ProcessResult res, URIReference uriRef)
    {
        // Normalize the scheme.
        res.scheme = new SchemeNormalizer().normalize(uriRef.getScheme());
    }


    private void processAuthority(ProcessResult res, URIReference uriRef)
    {
        // Normalize the authority.
        res.authority = new AuthorityNormalizer().normalize(
            uriRef.getAuthority(), uriRef.getCharset(), res.scheme);
    }


    private void processPath(ProcessResult res, URIReference uriRef)
    {
        // Normalize the path.
        res.path = new PathNormalizer().normalize(
            uriRef.getPath(), uriRef.getCharset(), uriRef.hasAuthority());
    }


    private void processQuery(ProcessResult res, URIReference uriRef)
    {
        // Normalize the query.
        res.query = new QueryNormalizer().normalize(
            uriRef.getQuery(), uriRef.getCharset());
    }


    private void processFragment(ProcessResult res, URIReference uriRef)
    {
        // Normalize the fragment.
        res.fragment = new FragmentNormalizer().normalize(
            uriRef.getFragment(), uriRef.getCharset());
    }
}
