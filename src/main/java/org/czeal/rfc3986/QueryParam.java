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


/**
 * A class representing a single {@code query} parameter with a key and a value.
 *
 * <p>
 * This class provides functionality to parse a {@code query} parameter from a
 * string and retrieve its key and value.
 * </p>
 *
 * @author Hideki Ikeda
 */
class QueryParam
{
    /**
     * Converts an input string into a {@link QueryParam} object, distinguishing
     * between key and value.
     *
     * <p>
     * This method parses strings of the form {@code "key=value"} into separate
     * "key" and "value" parts for the {@link QueryParam} object. If no {@code "="}
     * is present, the entire string is treated as the "key" with "value" being
     * {@code null}. The method only considers the first {@code "="} for splitting,
     * treating any subsequent {@code "="} as part of the "value".
     * </p>
     *
     * @param queryParams
     *         The query parameter string to parse.
     *
     * @return
     *         A new {@link QueryParam} object containing the parsed key and value.
     *
     * @throws NullPointerException
     *         If {@code input} is null.
     */
    static QueryParam parse(String queryParams)
    {
        if (queryParams == null)
        {
            throw newNPE("The input string must not be null.");
        }

        // Split the input string into two parts by the first "=" in the input string.
        String[] kv = queryParams.split("=", 2);

        // Set the key and value.
        String k = kv[0];

        // If the input string contains "=", set the value to the second element in the
        // array; otherwise, set it to null.
        String v = kv.length > 1 ? kv[1] : null;

        // Create a QueryParam object.
        return new QueryParam(k, v);
    }


    /**
     * The key of the query parameter.
     */
    private final String key;


    /**
     * The value of the query parameter.
     */
    private final String value;


    /**
     * Constructs a new {@link QueryParam} with the specified key and value.
     *
     * @param key
     *         The key of the {@code query} parameter. Cannot be {@code null}.
     *
     * @param value
     *         The value of the {@code query} parameter.
     *
     * @throws NullPointerException
     *         If the key is {@code null}.
     */
    QueryParam(String key, String value)
    {
        if (key == null)
        {
            throw newNPE("The key must not be null.");
        }

        this.key   = key;
        this.value = value;
    }


    /**
     * Gets the key of this {@code query} parameter.
     *
     * @return The key of the {@code query} parameter.
     */
    public String getKey()
    {
        return key;
    }


    /**
     * Gets the value of this {@code query} parameter.
     *
     * @return The value of the {@code query} parameter.
     */
    public String getValue()
    {
        return value;
    }


    /**
     * Returns a string representation of the query parameter.
     *
     * <p>
     * The string is in the format {@code "key=value"}. If the value is {@code null},
     * only the key is returned.
     * </p>
     *
     * @return A string representation of the query parameter.
     */
    @Override
    public String toString()
    {
        if (value == null)
        {
            // If the value is null, just return the key.
            return key;
        }

        // Concatenate the key and the value with "=".
        return String.join("=", key, value);
    }
}
