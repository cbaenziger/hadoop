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
import static org.junit.Assert.assertNotNull;
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
import java.net.SocketAddress;
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
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.ReferenceCountUtil;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.channel.embedded.EmbeddedChannel;
import org.apache.hadoop.hdfs.server.datanode.web.webhdfs.WebHdfsHandler;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.handler.codec.http.QueryStringDecoder;
import org.apache.hadoop.hdfs.server.common.HostRestrictingAuthorizationFilter;

import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus ;

import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hadoop.hdfs.server.datanode.web.HostRestrictingAuthorizationFilterHandler;
import org.apache.hadoop.hdfs.web.WebHdfsFileSystem;
import org.apache.hadoop.conf.Configuration;

public class TestHostRestrictingAuthorizationFilterHandler {
	
  final String CONFNAME = HostRestrictingAuthorizationFilter.HDFS_CONFIG_PREFIX +
	                      HostRestrictingAuthorizationFilter.RESTRICTION_CONFIG;	
	
  private Logger log = LoggerFactory.getLogger(TestHostRestrictingAuthorizationFilterHandler.class);
  
  /*
   * Custom channel implementation which allows for mocking a client's remote
   * address
   */
  protected class CustomEmbeddedChannel extends EmbeddedChannel{

	    private InetSocketAddress socketAddress;

	    /*
	     * A normal @{EmbeddedChannel} constructor which takes the remote client
	     * host and port to mock
	     */
	    public CustomEmbeddedChannel(String host, int port, final ChannelHandler ... handlers){
	        super(handlers);
	        socketAddress = new InetSocketAddress(host, port);
	    }

	    @Override
	    protected SocketAddress remoteAddress0(){
	        return this.socketAddress;
	    }
	}
  
  /*
   * Test running in with no ACL rules (restrict all)
   */
  @Test
  public void testRejectAll() throws Exception {
    EmbeddedChannel channel = new CustomEmbeddedChannel("127.0.0.1", 1006, new HostRestrictingAuthorizationFilterHandler());
    FullHttpRequest httpRequest = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                             HttpMethod.GET,
                                                             WebHdfsFileSystem.PATH_PREFIX + "/user/myName/fooFile?op=OPEN");
    // we will send back an error so ensure our write returns false
    assertFalse("Should get error back from handler for rejected request", channel.writeInbound(httpRequest));
    DefaultHttpResponse channelResponse = (DefaultHttpResponse) channel.outboundMessages().poll();
    assertNotNull("Expected response to exist.", channelResponse);
    assertTrue(channelResponse.getStatus().equals(HttpResponseStatus.FORBIDDEN));
    assertFalse(channel.isOpen());
  }

  /*
   * Test accepting multiple allowed GET requests to ensure channel can be reused
   */
  @Test
  public void testMultipleAcceptedGETsOneChannel() throws Exception {
	Configuration conf = new Configuration();
    conf.set(CONFNAME, "*,*,/allowed");
	HostRestrictingAuthorizationFilter filter = HostRestrictingAuthorizationFilterHandler.createFilter(conf);
	EmbeddedChannel channel = new CustomEmbeddedChannel("127.0.0.1", 1006, new HostRestrictingAuthorizationFilterHandler(filter));
	FullHttpRequest allowedHttpRequest = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                    HttpMethod.GET,
                                                                    WebHdfsFileSystem.PATH_PREFIX + "/allowed/file_one?op=OPEN");
	FullHttpRequest allowedHttpRequest2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                    HttpMethod.GET,
                                                                    WebHdfsFileSystem.PATH_PREFIX + "/allowed/file_two?op=OPEN");
	FullHttpRequest allowedHttpRequest3 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                   HttpMethod.GET,
                                                                   WebHdfsFileSystem.PATH_PREFIX + "/allowed/file_three?op=OPEN");
	assertTrue("Should successfully accept request", channel.writeInbound(allowedHttpRequest));
	assertTrue("Should successfully accept request, second time", channel.writeInbound(allowedHttpRequest2));
	assertTrue("Should successfully accept request, third time", channel.writeInbound(allowedHttpRequest3));
  }
  
  /*
   * Test accepting multiple allowed GET requests in different channels to a single filter instance
   */
  @Test
  public void testMultipleChannels() throws Exception {
	Configuration conf = new Configuration();
    conf.set(CONFNAME, "*,*,/allowed");
	HostRestrictingAuthorizationFilter filter = HostRestrictingAuthorizationFilterHandler.createFilter(conf);
	EmbeddedChannel channel1 = new CustomEmbeddedChannel("127.0.0.1", 1006, new HostRestrictingAuthorizationFilterHandler(filter));
	EmbeddedChannel channel2 = new CustomEmbeddedChannel("127.0.0.2", 1006, new HostRestrictingAuthorizationFilterHandler(filter));
	EmbeddedChannel channel3 = new CustomEmbeddedChannel("127.0.0.3", 1006, new HostRestrictingAuthorizationFilterHandler(filter));
	FullHttpRequest allowedHttpRequest = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                    HttpMethod.GET,
                                                                    WebHdfsFileSystem.PATH_PREFIX + "/allowed/file_one?op=OPEN");
	FullHttpRequest allowedHttpRequest2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                    HttpMethod.GET,
                                                                    WebHdfsFileSystem.PATH_PREFIX + "/allowed/file_two?op=OPEN");
	FullHttpRequest allowedHttpRequest3 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
                                                                   HttpMethod.GET,
                                                                   WebHdfsFileSystem.PATH_PREFIX + "/allowed/file_three?op=OPEN");
	assertTrue("Should successfully accept request", channel1.writeInbound(allowedHttpRequest));
	assertTrue("Should successfully accept request, second time", channel2.writeInbound(allowedHttpRequest2));
	
	// verify closing one channel does not affect remaining channels
	channel1.close();
	assertTrue("Should successfully accept request, third time", channel3.writeInbound(allowedHttpRequest3));
  }
  
  /*
   * Test accepting a GET request for the file checksum
   */
  @Test
  public void testAcceptGETFILECHECKSUM() throws Exception {
	EmbeddedChannel channel = new CustomEmbeddedChannel("127.0.0.1", 1006, new HostRestrictingAuthorizationFilterHandler());
	FullHttpRequest httpRequest = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
	                                                         HttpMethod.GET,
	                                                         WebHdfsFileSystem.PATH_PREFIX + "/user/myName/fooFile?op=GETFILECHECKSUM");
	assertTrue("Should successfully accept request", channel.writeInbound(httpRequest));
  }
}
