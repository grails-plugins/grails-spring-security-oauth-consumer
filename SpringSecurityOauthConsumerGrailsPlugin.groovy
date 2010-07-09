/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod
import org.springframework.security.oauth.common.signature.SharedConsumerSecret
import org.springframework.security.oauth.consumer.BaseProtectedResourceDetails
import org.springframework.security.oauth.consumer.CoreOAuthConsumerSupport
import org.springframework.security.oauth.consumer.InMemoryProtectedResourceDetailsService
import org.springframework.security.oauth.consumer.OAuthConsumerProcessingFilter
import org.springframework.security.oauth.consumer.net.DefaultOAuthURLStreamHandlerFactory
import org.springframework.security.oauth.consumer.nonce.UUIDNonceFactory
import org.springframework.security.oauth.consumer.token.HttpSessionBasedTokenServicesFactory
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.access.intercept.RequestKey
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.AntUrlPathMatcher
import org.springframework.security.web.util.RegexUrlPathMatcher
import org.springframework.util.StringUtils

class SpringSecurityOauthConsumerGrailsPlugin {

	String version = '0.1'
	String grailsVersion = '1.2.2 > *'
	Map dependsOn = ['springSecurityCore': '0.4 > *']

	List pluginExcludes = [
		'docs/**',
		'src/docs/**'
	]

	String author = 'Burt Beckwith'
	String authorEmail = 'beckwithb@vmware.com'
	String title = 'OAuth Consumer support for the Spring Security plugin.'
	String description = 'OAuth Consumer support for the Spring Security plugin.'

	String documentation = 'http://grails.org/plugin/spring-security-oauth-consumer'

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		println 'Configuring Spring Security OAuth Consumer ...'

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuthConsumerSecurityConfig'
		// have to get again after overlaying DefaultOAuthConsumerSecurityConfig
		conf = SpringSecurityUtils.securityConfig

		SpringSecurityUtils.registerFilter 'oauthConsumerFilter',
				SecurityFilterPosition.LAST.order - 1

		def resources = parseResources(conf)
		oauthProtectedResourceDetailsService(InMemoryProtectedResourceDetailsService) {
			resourceDetailsStore = resources
		}

		oauthSignatureMethodFactory(CoreOAuthSignatureMethodFactory) {
			supportPlainText = conf.oauthConsumer.signature.supportPlainText // false
			supportHMAC_SHA1 = conf.oauthConsumer.signature.supportHMAC_SHA1 // true
			supportRSA_SHA1 = conf.oauthConsumer.signature.supportRSA_SHA1 // true
		}

		oauthNonceFactory(UUIDNonceFactory)

		oauthStreamHandlerFactory(DefaultOAuthURLStreamHandlerFactory)

		oauthProxySelector(ProxySelector) { bean ->
			bean.factoryMethod = 'getDefault'
		}
 
		oauthConsumerSupport(CoreOAuthConsumerSupport) {
			connectionTimeout = conf.oauthConsumer.protectedResource.connectionTimeout // 1000 * 60
			readTimeout = conf.oauthConsumer.protectedResource.readTimeout // 1000 * 60
			signatureFactory = ref('oauthSignatureMethodFactory')
			protectedResourceDetailsService = ref('oauthProtectedResourceDetailsService')
			nonceFactory = ref('oauthNonceFactory')
			streamHandlerFactory = ref('oauthStreamHandlerFactory')
			proxySelector = ref('oauthProxySelector')
		}

		oauthTokenServicesFactory(HttpSessionBasedTokenServicesFactory)

		oauthFailureEntryPoint(LoginUrlAuthenticationEntryPoint) {
			forceHttps = conf.auth.forceHttps // false
			useForward = conf.auth.useForward // false
			loginFormUrl = conf.oauthConsumer.failurePage
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
		}

		String pathType = conf.oauthConsumer.ods.pathType // 'ant'
		def urlMatcher = 'ant'.equals(pathType) ? new AntUrlPathMatcher() : new RegexUrlPathMatcher()
		urlMatcher.requiresLowerCaseUrl = conf.oauthConsumer.ods.lowercaseComparisons // true

		LinkedHashMap<RequestKey, Collection<ConfigAttribute>> invocationDefinitionMap = [:]
		for (Map<String, String> map : conf.oauthConsumer.ods.urls) {
			String path = map.pattern
			if (conf.oauthConsumer.ods.lowercaseComparisons) {
				path = path.toLowerCase()
			}
			if (map.resources) {
				invocationDefinitionMap[new RequestKey(path, map.httpMethod ?: null)] = SecurityConfig.createList(
					StringUtils.commaDelimitedListToStringArray(map.resources))
			}
		}

 		oauthObjectDefinitionSource(DefaultFilterInvocationSecurityMetadataSource, urlMatcher, invocationDefinitionMap)

		oauthConsumerFilter(OAuthConsumerProcessingFilter) {
			protectedResourceDetailsService = ref('oauthProtectedResourceDetailsService')
			OAuthFailureEntryPoint = ref('oauthFailureEntryPoint')
			tokenServicesFactory = ref('oauthTokenServicesFactory')
			objectDefinitionSource = ref('oauthObjectDefinitionSource')
			consumerSupport = ref('oauthConsumerSupport')
			portResolver = ref('portResolver')
			requireAuthenticated = conf.oauthConsumer.consumerFilter.requireAuthenticated // true
			accessTokensRequestAttribute = conf.oauthConsumer.consumerFilter.accessTokensRequestAttribute // 'OAUTH_ACCESS_TOKENS'
		}
	}

	private Map<String, BaseProtectedResourceDetails> parseResources(conf) {
		Map<String, BaseProtectedResourceDetails> resources = new TreeMap<String, BaseProtectedResourceDetails>()

		for (Map<String, Object> resourceDef in conf.oauthConsumer.resourceDefs) {
			BaseProtectedResourceDetails resource = new BaseProtectedResourceDetails()

			setIfString 'id',                          resourceDef, resource, 'A resource id'
			setIfString 'consumerKey',                 resourceDef, resource, 'A consumer key'
			setIfString 'requestTokenURL',             resourceDef, resource, 'A request token URL'
			setIfString 'accessTokenURL',              resourceDef, resource, 'An access token URL'
			setIfString 'accessTokenHttpMethod',       resourceDef, resource
			setIfString 'userAuthorizationURL',        resourceDef, resource, 'A user authorization URL'
			setIfString 'authorizationHeaderRealm'   , resourceDef, resource
			setIfBoolean 'acceptsAuthorizationHeader', resourceDef, resource
			setIfBoolean 'use10a',                     resourceDef, resource

			def secret = resourceDef.secret
			if (secret instanceof String && secret) {
				resource.sharedSecret = new SharedConsumerSecret(secret)
			}
			else {
				error "A shared secret must be supplied with the definition of a resource: $resourceDef"
			}

			def signatureMethod = resourceDef.signatureMethod
			if (!(signatureMethod instanceof String && signatureMethod)) {
				signatureMethod = HMAC_SHA1SignatureMethod.SIGNATURE_NAME
			}
			resource.signatureMethod = signatureMethod

			def additionalParameters = resourceDef.addtionalParameters
			if (additionalParameters instanceof Map && additionalParameters) {
				resource.additionalParameters = additionalParameters
			}

			def additionalRequestHeaders = resourceDef.additionalRequestHeaders
			if (additionalRequestHeaders instanceof Map && additionalRequestHeaders) {
				resource.additionalRequestHeaders = additionalRequestHeaders
			}

			resources[resourceDef.id] = resource
		}

		resources
	}

	private void setIfString(String attrName, Map<String, Object> resourceDef,
			BaseProtectedResourceDetails resource, String errorPrefix = null) {

		def value = resourceDef."$attrName"
		if (value instanceof String && value) {
			resource."$attrName" = value
			return
		}

		if (errorPrefix) {
			error "$errorPrefix must be supplied with the definition of a protected resource: $resourceDef"
		}
	}

	private void setIfBoolean(String attrName, Map<String, Object> resourceDef, BaseProtectedResourceDetails resource) {
		def value = resourceDef."$attrName"
		if (value instanceof Boolean) {
			resource."$attrName" = value
		}
	}

	private void error(String message) {
		// OAuth parser throws BeanDefinitionParsingException but Problem/Location aren't as necessary in Grails
		throw new RuntimeException(message) 
	}
}
