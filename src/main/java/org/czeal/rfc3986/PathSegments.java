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


import static org.czeal.rfc3986.Utils.newNPE;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * A class representing a collection of {@code path} segments in a URI reference.
 *
 * <p>
 * This class provides functionality to parse, add, and manage individual path segments
 * of a URI reference, handling them as a list of strings.
 * </p>
 *
 * @author Hideki Ikeda
 */
class PathSegments
{
    /**
     * Parses a string input into a {@link PathSegments} object.
     *
     * <p>
     * The input string is split into segments based on {@code "/"} delimiters.
     * Each segment is treated as a separate path component.
     * </p>
     *
     * @param pathSegments
     *         The string input representing path segments.
     *
     * @return
     *         A new {@link PathSegments} object containing the parsed segments,
     *         or {@code null} if the input is {@code null}.
     */
    static PathSegments parse(String pathSegments)
    {
        if (pathSegments == null)
        {
            return null;
        }

        // Convert the input string to a list of Strings.
        List<String> segments = new ArrayList<>( Arrays.asList(pathSegments.split("/", -1)) );

        // Create a PathSegments object.
        return new PathSegments(segments);
    }


    /**
     * Internal storage for path segments.
     */
    private final List<String> segments;


    /**
     * Creates an empty {@link PathSegments} instance.
     *
     * <p>
     * This constructor initializes the internal list of segments as empty.
     * </p>
     */
    public PathSegments()
    {
        this(new ArrayList<>(0));
    }


    /**
     * Creates a {@link PathSegments} instance with a predefined list of segments.
     *
     * <p>
     * This constructor allows for initializing the path segments from an existing
     * list.
     * </p>
     *
     * @param segments
     *         A list of strings representing path segments.
     *
     * @throws NullPointerException
     *         if the provided list of segments is {@code null}.
     */
    public PathSegments(List<String> segments)
    {
        if (segments == null)
        {
            throw newNPE("params must not be null.");
        }

        this.segments = segments;
    }


    /**
     * Adds one or more path segments to the current {@link PathSegments} instance.
     * Each segment is appended in order to the internal list of segments.
     *
     * @param segments
     *         An array of strings representing additional path segments to be added.
     *
     * @return
     *         {@code this} object.
     *
     * @throws NullPointerException
     *         if the provided array of segments, or any individual segment, is
     *         {@code null}.
     */
    public PathSegments add(String... segments)
    {
        if (segments == null)
        {
            throw newNPE("The segments must not be null.");
        }

        for (String s : segments)
        {
            if (s == null)
            {
                throw newNPE("A segment must not be null.");
            }
        }

        // Add the given segments.
        Collections.addAll(this.segments, segments);

        // Return this object.
        return this;
    }


    /**
     * Returns a string representation of the path segments.
     *
     * <p>
     * The segments are concatenated with "/" as a delimiter.
     * </p>
     *
     * @return
     *         A string representation of the path segments, or an empty string
     *         if there are no segments.
     */
    @Override
    public String toString()
    {
        if (segments == null)
        {
            return "";
        }

        return String.join("/", segments);
    }
}
