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


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * <p>
 * Validates for "path" component of a URI reference according to the syntax defined
 * in <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.3">RFC 3986, 3.3.
 * Path</a> and <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 * Appendix A. Collected ABNF for URI</a> as follows.
 * </p>
 *
 * <blockquote>
 * <pre style="font-family: 'Menlo', 'Courier', monospace;">{@code
 * <u>RFC 3986, 3.3. Path</u>
 *
 *   If a URI contains an authority component, then the path component must
 *   either be empty or begin with a slash ("/") character. If a URI does
 *   not contain an authority component, then the path cannot begin with
 *   two slash characters ("//"). In addition, a URI reference (Section 4.1)
 *   may be a relative-path reference, in which case the first path segment
 *   cannot contain a colon (":") character.
 *
 * <u>RFC 3986, Appendix A. Collected ABNF for URI</u>
 *
 *   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 *   hier-part     = "//" authority path-abempty
 *                 / path-absolute
 *                 / path-rootless
 *                 / path-empty
 *
 *   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
 *
 *   relative-part = "//" authority path-abempty
 *                 / path-absolute
 *                 / path-noscheme
 *                 / path-empty
 *
 *   path-abempty  = *( "/" segment )
 *   path-absolute = "/" [ segment-nz *( "/" segment ) ]
 *   path-noscheme = segment-nz-nc *( "/" segment )
 *   path-rootless = segment-nz *( "/" segment )
 *   path-empty    = <pchar>
 * }</pre>
 * </blockquote>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#section-3.3">RFC 3986,
 *      3.3. Path</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc3986#appendix-A">RFC 3986,
 *      Appendix A. Collected ABNF for URI</a>
 *
 * @author Hideki Ikeda
 */
class PathValidator
{
    /**
     * Validates a path value.
     *
     * @param path
     *         A path value.
     *
     * @param charset
     *         The charset used for percent-encoding the path value.
     *
     * @param relativeReference
     *         Whether or not the URI reference is a relative reference.
     *
     * @param hasAuthority
     *         Whether or not the URI reference has an authority.
     */
    void validate(
        String path, Charset charset, boolean relativeReference, boolean hasAuthority)
    {
        // RFC 3986, 3.3. Path
        //
        //   If a URI contains an authority component, then the path component must
        //   either be empty or begin with a slash ("/") character. If a URI does
        //   not contain an authority component, then the path cannot begin with
        //   two slash characters ("//"). In addition, a URI reference (Section 4.1)
        //   may be a relative-path reference, in which case the first path segment
        //   cannot contain a colon (":") character.
        //

        // RFC 3986, Appendix A. Collected ABNF for URI
        //
        //   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
        //
        //   hier-part     = "//" authority path-abempty
        //                 / path-absolute
        //                 / path-rootless
        //                 / path-empty
        //
        //   relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
        //
        //   relative-part = "//" authority path-abempty
        //                 / path-absolute
        //                 / path-noscheme
        //                 / path-empty
        //
        //   path-abempty  = *( "/" segment )
        //   path-absolute = "/" [ segment-nz *( "/" segment ) ]
        //   path-noscheme = segment-nz-nc *( "/" segment )
        //   path-rootless = segment-nz *( "/" segment )
        //   path-empty    = 0<pchar>
        //

        // If the authority is contained in the URI reference.
        if (hasAuthority)
        {
            validatePathAbempty(path, charset);
            return;
        }

        // Validate the value as a "path-abempty".
        try
        {
            validatePathEmpty(path);
            return;
        }
        catch (Throwable t)
        {
        }

        // Validate the value as a "path-absolute".
        try
        {
            validatePathAbsolute(path, charset);
            return;
        }
        catch (Throwable t)
        {
        }

        // If the URI reference is a relative reference, validate the value as a
        // "path-rootless"; otherwise, validate the value as a "path-noscheme".
        if (relativeReference)
        {
            validatePathNoscheme(path, charset);
        }
        else
        {
            validatePathRootless(path, charset);
        }
    }


    private void validatePathAbempty(String path, Charset charset)
    {
        if (path == null || path.isEmpty())
        {
            // null or an empty value is allowed.
            return;
        }

        // Ensure the path starts with a slash.
        ensurePathStartsWithSlash(path);

        if (path.length() == 1)
        {
            // The path only contains the first slash.
            return;
        }

        // The path segments.
        String[] segments = path.substring(1).split("/", -1);

        // Validate each segment.
        for (int i = 0; i < segments.length; i++)
        {
            new SegmentValidator().validate(segments[i], charset);
        }
    }


    private void validatePathAbsolute(String path, Charset charset)
    {
        // Ensure the path is not empty.
        ensurePathNotEmpty(path);

        // Ensure the path starts with a slash.
        ensurePathStartsWithSlash(path);

        if (path.length() == 1)
        {
            // The path only contains the first slash.
            return;
        }

        // Split the path into segments.
        String[] segments = path.substring(1).split("/", -1);

        // Validate the first element.
        new SegmentNzValidator().validate(segments[0], charset);

        // Validate remaining segments.
        for (int i = 1; i < segments.length; i++)
        {
            new SegmentValidator().validate(segments[i], charset);
        }
    }


    private void validatePathNoscheme(String path, Charset charset)
    {
        // Ensure the path is not empty.
        ensurePathNotEmpty(path);

        // Split the path into segments.
        String[] segments = path.split("/", -1);

        // Validate the first element.
        new SegmentNzNcValidator().validate(segments[0], charset);

        // Validate the remaining segments.
        for (int i = 1; i < segments.length; i++)
        {
            new SegmentValidator().validate(segments[i], charset);
        }
    }


    private void validatePathRootless(String path, Charset charset)
    {
        // Ensure the path is not empty.
        ensurePathNotEmpty(path);

        // Split the path into segments.
        String[] segments = path.split("/", -1);

        // Validate the first element.
        new SegmentNzValidator().validate(segments[0], charset);

        // Validate the remaining segments.
        for (int i = 1; i < segments.length; i++)
        {
            new SegmentValidator().validate(segments[i], charset);
        }
    }


    private void validatePathEmpty(String path)
    {
        if (!path.isEmpty())
        {
            // The path must not be empty.
            throw newIAE("The path must be empty");
        }
    }


    private void ensurePathNotEmpty(String path)
    {
        if (path == null || path.isEmpty())
        {
            // The path must not be empty.
            throw newIAE("The path must not be empty.");
        }
    }


    private void ensurePathStartsWithSlash(String path)
    {
        if (!path.startsWith("/"))
        {
            // The path-abempty must start with a slash.
            throw newIAE("The path must start with a slash.");
        }
    }
}
