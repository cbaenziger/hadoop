/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdfs.server.datanode.web;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.lang.StringBuffer;
import java.util.Arrays;
import java.util.Vector;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.net.InetSocketAddress;
import com.google.common.net.InetAddresses;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.netty.handler.codec.http.HttpRequest;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpVersion;

import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hadoop.hdfs.server.datanode.web.HostRestrictingAuthorizationFilterHandler;
import org.apache.hadoop.hdfs.web.WebHdfsFileSystem;
import org.apache.hadoop.conf.Configuration;

public class TestHostRestrictingAuthorizationFilterHandler {
  private Logger log = LoggerFactory.getLogger(TestHostRestrictingAuthorizationFilterHandler.class);

  /*
   * Test running in with no ACL rules (restrict all)
   */
  @Test
  public void testRejectAll() throws Exception {
   // XXX how to inject this for the classpath based Configuration?
   // Configuration conf = new HdfsConfiguration();
   // String confName = HostRestrictingAuthorizationFilter.HDFS_CONFIG_PREFIX +
   //                   HostRestrictingAuthorizationFilter.RESTRICTION_CONFIG;
   // String allowRule = "*,*,/";
   // conf.set(confName, allowRule);

    ChannelHandlerContext context = Mockito.mock(ChannelHandlerContext.class);
    Mockito.when(context.channel().remoteAddress())
      .thenReturn(new InetSocketAddress(InetAddresses.forString("192.168.1.2"), 32768));

    HostRestrictingAuthorizationFilterHandler handler = new HostRestrictingAuthorizationFilterHandler();

    DefaultFullHttpRequest fullHttpRequest = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                            HttpMethod.GET,
                                                            WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/foo&op=OPEN");
    handler.channelRead(context, fullHttpRequest);
// How to mock these?
//      HttpResponseStatus status = new HttpResponseStatus(code, message);
//      sendResponseAndClose(context, new DefaultHttpResponse(HTTP_1_1, status));
  }


  /*
   * Test accepting a GET request for the file checksum when prohibited from doing
   * a GET open call
   */
/*
  @Test
  public void testAcceptGETFILECHECKSUM() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/").toString());
    Mockito.when(request.getQueryString()).thenReturn("op=GETFILECHECKSUM ");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
    Mockito.verify(response, Mockito.times(0)).sendError(Mockito.eq(HttpServletResponse.SC_FORBIDDEN),
        Mockito.anyString());
  }
*/

  /*
   * Test accepting a GET request for reading a file via an open call
   */
/*
  @Test
  public void testRuleAllowedGet() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/foo").toString());
    Mockito.when(request.getQueryString()).thenReturn("op=OPEN");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    String allowRule = "ubuntu,127.0.0.1/32,/localbits/*|ubuntu,192.168.0.1/22,/user/ubuntu/*";
    configs.put("host.allow.rules", allowRule);
    configs.put(AuthenticationFilter.AUTH_TYPE, "simple");
  }

*/

  /*
   * Test by default we deny an open call GET request
   */
/*
  @Test
  public void testRejectsGETs() throws Exception {
    HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRemoteAddr()).thenReturn(null);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getRequestURI())
        .thenReturn(new StringBuffer(WebHdfsFileSystem.PATH_PREFIX + "/user/ubuntu/bar&foo&op=GETCONTENTSUMMARY").toString());
    Mockito.when(request.getQueryString()).thenReturn("delegationToken=foo&op=OPEN ");
    Mockito.when(request.getRemoteAddr()).thenReturn("192.168.1.2");

    HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    FilterChain chain = new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
          throws IOException, ServletException {
      }
    };

    Filter filter = new HostRestrictingAuthorizationFilter();

    HashMap configs = new HashMap<String, String>() {
    };
    configs.put(AuthenticationFilter.AUTH_TYPE, "simple");
    FilterConfig fc = new DummyFilterConfig(configs);

    filter.init(fc);
    filter.doFilter(request, response, chain);
    Mockito.verify(response).sendError(Mockito.eq(HttpServletResponse.SC_FORBIDDEN), Mockito.anyString());
    filter.destroy();
  }
*/
}
