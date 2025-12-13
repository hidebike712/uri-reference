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


import static org.czeal.rfc3986.TestUtils.assertThrowsIAE;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import org.junit.jupiter.api.Test;


public class IpvFutureValidatorTest
{
    @Test
    public void test_validate()
    {
        assertDoesNotThrow(
            () -> new IpvFutureValidator().validate("v1.fe80::a+en1"));

        assertThrowsIAE(
            "The host value \"[]\" is invalid because the content enclosed by brackets does not form a valid IPvFuture address as it is empty.",
            () -> new IpvFutureValidator().validate(""));

        assertThrowsIAE(
            "The host value \"[v1]\" is invalid because the content enclosed by brackets does not form a valid IPvFuture address due to missing periods.",
            () -> new IpvFutureValidator().validate("v1"));

        assertThrowsIAE(
            "The host value \"[v.fe80::a+en1]\" is invalid because the content enclosed by brackets does not form a valid IPvFuture address due to missing its version.",
            () -> new IpvFutureValidator().validate("v.fe80::a+en1"));

        assertThrowsIAE(
            "The host value \"[v.fe80::a+en1]\" is invalid because the content enclosed by brackets does not form a valid IPvFuture address due to missing its version.",
            () -> new IpvFutureValidator().validate("v.fe80::a+en1"));

        assertThrowsIAE(
            "The host value \"[v1.]\" is invalid because the content enclosed by brackets does not form a valid IPvFuture address as there is no content following the first period.",
            () -> new IpvFutureValidator().validate("v1."));

        assertThrowsIAE(
            "The host value \"[v1./fe80::a+en1]\" is invalid because the content enclosed by brackets does not form a valid IPvFuture address due to the segment after the first period \"/fe80::a+en1\", containing an invalid character \"/\" at the index 0.",
            () -> new IpvFutureValidator().validate("v1./fe80::a+en1"));
    }
}
