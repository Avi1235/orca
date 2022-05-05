/*
 * Copyright 2022 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.config

import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain
import com.amazonaws.services.rds.auth.GetIamAuthTokenRequest
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.sql.Connection
import java.sql.DriverManager
import java.util.*

class GenerateAuthTokenPassword {
  companion object {
    private val creds : DefaultAWSCredentialsProviderChain = DefaultAWSCredentialsProviderChain()
    private val AWS_ACCESS_KEY = creds.credentials.awsAccessKeyId
    private val AWS_SECRET_KEY = creds.credentials.awsSecretKey

    private val RDS_INSTANCE_HOSTNAME = "your host"
    private val RDS_INSTANCE_PORT = 3306
    private val REGION_NAME = "us-west-2"
    private val DB_USER = "orca_migrate"
    private val JDBC_URL = "jdbc:mysql://$RDS_INSTANCE_HOSTNAME:$RDS_INSTANCE_PORT"

    private val SSL_CERTIFICATE = "rds-ca-2019-us-west-2.pem"

    private val KEY_STORE_TYPE = "JKS"
    private val KEY_STORE_PROVIDER = "SUN"
    private val KEY_STORE_FILE_PREFIX = "sys-connect-via-ssl-test-cacerts"
    private val KEY_STORE_FILE_SUFFIX = ".jks"
    private val DEFAULT_KEY_STORE_PASSWORD = "changeit"

    /**
     * This method sets the mysql connection properties which includes the IAM Database Authentication
     * token as the password. It also specifies that SSL verification is required.
     *
     * @return
     */
    private fun setMySqlConnectionProperties(): Properties? {
      val mysqlConnectionProperties = Properties()
      //		mysqlConnectionProperties.setProperty("verifyServerCertificate","true");
      mysqlConnectionProperties.setProperty("useSSL", "true")
      mysqlConnectionProperties.setProperty("user", DB_USER)
      mysqlConnectionProperties.setProperty("password", generateAuthToken(DB_USER))
      return mysqlConnectionProperties
    }

    /**
     * This method generates the IAM Auth Token. An example IAM Auth Token would look like follows:
     * btusi123.cmz7kenwo2ye.rds.cn-north-1.amazonaws.com.cn:3306/?Action=connect&DBUser=iamtestuser&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20171003T010726Z&X-Amz-SignedHeaders=host&X-Amz-Expires=899&X-Amz-Credential=AKIAPFXHGVDI5RNFO4AQ%2F20171003%2Fcn-north-1%2Frds-db%2Faws4_request&X-Amz-Signature=f9f45ef96c1f770cdad11a53e33ffa4c3730bc03fdee820cfdf1322eed15483b
     *
     * @return
     */

    fun generateAuthToken(user : String?): String? {
      val awsCredentials = BasicAWSCredentials(AWS_ACCESS_KEY, AWS_SECRET_KEY)
      val generator: RdsIamAuthTokenGenerator = RdsIamAuthTokenGenerator.builder()
        .credentials(AWSStaticCredentialsProvider(awsCredentials))
        .region(REGION_NAME)
        .build()
      return generator.getAuthToken(
        GetIamAuthTokenRequest.builder()
          .hostname(RDS_INSTANCE_HOSTNAME)
          .port(RDS_INSTANCE_PORT)
          .userName(user)
          .build()
      )
    }

    /**
     * This method sets the SSL properties which specify the key store file, its type and password:
     *
     * @throws Exception
     */
    @Throws(Exception::class)
    private fun setSslProperties() {
      System.setProperty("javax.net.ssl.trustStore", createKeyStoreFile())
      System.setProperty("javax.net.ssl.trustStoreType", KEY_STORE_TYPE)
      System.setProperty("javax.net.ssl.trustStorePassword", DEFAULT_KEY_STORE_PASSWORD)
    }

    @Throws(Exception::class)
    fun getDBConnectionUsingIam(): Connection? {
      //		setSslProperties();
      return DriverManager.getConnection(JDBC_URL, setMySqlConnectionProperties())
    }

    /**
     * This method returns the path of the Key Store File needed for the SSL verification during the
     * IAM Database Authentication to the db instance.
     *
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    private fun createKeyStoreFile(): String? {
      return createKeyStoreFile(createCertificate()).path
    }

    /**
     * This method generates the SSL certificate
     *
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    private fun createCertificate(): X509Certificate {
      val certFactory = CertificateFactory.getInstance("X.509")
      val url = File(SSL_CERTIFICATE).toURI().toURL() ?: throw Exception()
      url.openStream()
        .use { certInputStream -> return certFactory.generateCertificate(certInputStream) as X509Certificate }
    }

    /**
     * This method creates the Key Store File
     *
     * @param rootX509Certificate - the SSL certificate to be stored in the KeyStore
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    private fun createKeyStoreFile(rootX509Certificate: X509Certificate): File {
      val keyStoreFile = File.createTempFile(KEY_STORE_FILE_PREFIX, KEY_STORE_FILE_SUFFIX)
      FileOutputStream(keyStoreFile.path).use { fos ->
        val ks = KeyStore.getInstance(KEY_STORE_TYPE, KEY_STORE_PROVIDER)
        ks.load(null)
        ks.setCertificateEntry("rootCaCertificate", rootX509Certificate)
        ks.store(fos, DEFAULT_KEY_STORE_PASSWORD.toCharArray())
      }
      return keyStoreFile
    }
  }
}
