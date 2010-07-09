/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
security {
	oauthConsumer {
		failurePage = null // must be specified
		resourceDefs = null // must be specified
		consumerFilter {
			requireAuthenticated = true
			accessTokensRequestAttribute = 'OAUTH_ACCESS_TOKENS'
		}
		protectedResource {
			connectionTimeout = 1000 * 60
			readTimeout = 1000 * 60
		}
		signature {
			supportPlainText = false
			supportHMAC_SHA1 = true
			supportRSA_SHA1 = true
		}
		ods {
			pathType = 'ant'
			lowercaseComparisons = true
			urls = [] // must be specified
		}
	}
}
