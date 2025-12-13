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
import java.util.List;
import java.util.stream.Collectors;


/**
 * <p>
 * <i>NOTE: This class is intended for internal use only.</i>
 * </p>
 *
 * A class representing a collection of {@code query} parameters.
 *
 * <p>
 * This class provides functionality to parse a string of {@code query} parameters,
 * add, replace, and remove parameters, and convert the collection back to a string
 * format.
 * </p>
 *
 * @author Hideki Ikeda
 */
class QueryParams
{
    /**
     * Parses the input string to create a new {@link QueryParams} object.
     *
     * <p>
     * This method processes an input string containing query parameters and constructs
     * a corresponding {@link QueryParams} instance. The input string should be
     * in the format of a query string, such as {@code "key1=value1&key2=value2"}.
     * Each key-value pair is separated by the {@code "&"} character, and each key
     * is separated from its value by the {@code "="} character.
     * </p>
     *
     * <p>
     * If the input string is {@code null}, this method returns {@code null}. If a segment
     * of the input string does not contain an {@code "="} character, that segment
     * is interpreted as a key with a {@code null} value. If the same key appears
     * multiple times with different values (e.g., {@code "key1=value1&key1=value2"}),
     * each occurrence is added as a separate {@link QueryParam} object in the
     * {@link QueryParams} object.
     * </p>
     *
     * @param queryParams
     *         The input string representation of query parameters, formatted as {@code
     *         "key1=value1&key2=value2"}. It can be {@code null}, in which case
     *         the method returns {@code null}.
     *
     * @return
     *         A new {@link QueryParams} object representing the parsed parameters.
     *         Returns {@code null} if the input string is {@code null}.
     */
    static QueryParams parse(String queryParams)
    {
        if (queryParams == null)
        {
            return null;
        }

        // Convert the input string to a list of QueryPrams.
        List<QueryParam> params = Arrays.stream(queryParams.split("&", -1))
                                        .map(e -> QueryParam.parse(e))
                                        .collect(Collectors.toList());

        // Create a Query object.
        return new QueryParams(params);
    }


    /**
     * Internal storage for query parameters.
     */
    private List<QueryParam> params;


    /**
     * Constructs an empty {@link QueryParams} object.
     */
    QueryParams()
    {
        this(new ArrayList<>(0));
    }


    /**
     * Constructs a {@link QueryParams} object with the specified list of parameters.
     *
     * @param params
     *         The list of {@link QueryParam} objects to be included in the {@link
     *         QueryParams}.
     *
     * @throws NullPointerException
     *         If the provided list of parameters is {@code null}.
     */
    QueryParams(List<QueryParam> params)
    {
        if (params == null)
        {
            throw newNPE("The params must not be null.");
        }

        this.params = params;
    }


    /**
     * Adds a new parameter to the collection.
     *
     * @param key
     *         The key of the query parameter.
     *
     * @param value
     *         The value of the query parameter.
     *
     * @return
     *         {@code this} object.
     */
    QueryParams add(String key, String value)
    {
        params.add(new QueryParam(key, value));

        return this;
    }


    /**
     * Replaces the value of an existing parameter. If the key does not exist, no
     * action is taken.
     *
     * @param key
     *         The key of the query parameter to replace.
     *
     * @param value
     *         The new value for the query parameter.
     *
     * @return
     *         {@code this} object.
     */
    QueryParams replace(String key, String value)
    {
        params = params.stream()
                       .map(e -> e.getKey().equals(key) ? new QueryParam(key, value) : e)
                       .collect(Collectors.toList());

        return this;
    }


    /**
     * Removes a parameter from the collection based on its key. If the key does
     * not exist, no action is taken.
     *
     * @param key
     *         The key of the query parameter to remove.
     *
     * @return
     *         {@code this} object.
     */
    QueryParams remove(String key)
    {
        params = params.stream()
                       .filter(e -> !e.getKey().equals(key))
                       .collect(Collectors.toList());

        return this;
    }


    /**
     * Returns whether this query parameters is empty or not.
     *
     * @return
     *         Whether this query parameters is empty or not.
     */
    boolean isEmpty()
    {
        return params.isEmpty();
    }


    /**
     * Returns a string representation of the {@code query} parameters in this
     * collection.
     *
     * @return
     *         A string representation of the {@code query} parameters, formatted
     *         as {@code "key1=value1&key2=value2"}.
     */
    @Override
    public String toString()
    {
        return params.stream()
                     .map(QueryParam::toString)
                     .collect(Collectors.joining("&"));
    }
}
