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

import static io.netty.handler.codec.http.HttpHeaders.Names.CONNECTION;
import static io.netty.handler.codec.http.HttpHeaders.Values.CLOSE;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;
import static io.netty.handler.codec.http.HttpVersion.HTTP_1_1;

import java.net.InetSocketAddress;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.FilterChain;

import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultHttpResponse;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.util.ReferenceCountUtil;

import org.apache.commons.logging.Log;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.server.common.HostRestrictingAuthorizationFilter;
import org.apache.hadoop.hdfs.server.common.HostRestrictingAuthorizationFilter.HttpInteraction;
import org.apache.hadoop.hdfs.web.resources.UserParam;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.hdfs.server.datanode.web.DatanodeHttpServer;

/**
 * Netty handler that integrates with the {@link HostRestrictingAuthorizationFilter}.  If
 * the filter determines that the request is allowed, then this handler forwards
 * the request to the next handler in the Netty pipeline.  Otherwise, this
 * handler drops the request and sends an HTTP 403 response.
 */
@InterfaceAudience.Private
final class HostRestrictingAuthorizationFilterHandler
    extends SimpleChannelInboundHandler<HttpRequest> {

  private static final Log LOG = DatanodeHttpServer.LOG;

  private final HostRestrictingAuthorizationFilter hostRestrictingAuthorizationFilter;
  private final Configuration conf;

  /**
   * Creates a new HostRestrictingAuthorizationFilterHandler.  There will be a new
   * instance created for each new Netty channel/pipeline serving a new request.
   * To prevent the cost of repeated initialization of the filter, this
   * constructor requires the caller to pass in a pre-built, fully initialized
   * filter instance.  The filter is stateless after initialization, so it can
   * be shared across multiple Netty channels/pipelines.
   *
   * @param hostRestrictingAuthorizationFilter initialized filter
   * @param conf Hadoop configuration object
   */
  public HostRestrictingAuthorizationFilterHandler(
      HostRestrictingAuthorizationFilter hostRestrictingAuthorizationFilter, Configuration conf) {
    this.conf = conf;
    this.hostRestrictingAuthorizationFilter = hostRestrictingAuthorizationFilter;
  }

  @Override
  protected void channelRead0(final ChannelHandlerContext ctx,
      final HttpRequest req) throws Exception {
    handleHttpInteraction(new NettyHttpInteraction(ctx, req));
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
    LOG.error("Exception in " + this.getClass().getSimpleName(), cause);
    sendResponseAndClose(ctx,
        new DefaultHttpResponse(HTTP_1_1, INTERNAL_SERVER_ERROR));
  }

  /**
   * Finish handling this pipeline by writing a response with the
   * "Connection: close" header, flushing, and scheduling a close of the
   * connection.
   *
   * @param ctx context to receive the response
   * @param resp response to send
   */
  private static void sendResponseAndClose(ChannelHandlerContext ctx,
      DefaultHttpResponse resp) {
    resp.headers().set(CONNECTION, CLOSE);
    ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
  }

  // XXX for initing the filter:
  //  Map<String, String> hostRestrictingAuthorizationParams = hostRestrictingAuthorizationFilter
  //    .getFilterParams(conf, HostRestrictingAuthorizationFilter.RESTRICTION_CONFIG);

  /**
   * Handles an {@link HttpInteraction} by applying the filtering logic.
   *
   * @param httpInteraction caller's HTTP interaction
   * @throws IOException if there is an I/O error
   * @throws ServletException if the implementation relies on the servlet API
   *     and a servlet API call has failed
   */
  public void handleHttpInteraction(HttpInteraction httpInteraction)
      throws IOException, ServletException {
    // a mock filterChain
    FilterChain chain = new FilterChain() {
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse)
          throws IOException, ServletException {
      }
    };

    // run the filter
    hostRestrictingAuthorizationFilter.doFilter((ServletRequest)httpInteraction, (ServletResponse)httpInteraction, chain);

    // if we did not call sendError to commit, then continue on
    if (!httpInteraction.isCommitted()) {
      httpInteraction.proceed();
    }
  }

  /**
   * {@link HttpInteraction} implementation for use in a Netty pipeline.
   */
  private static final class NettyHttpInteraction implements HttpInteraction {

    private final ChannelHandlerContext ctx;
    private final HttpRequest req;
    private boolean committed;

    /**
     * Creates a new NettyHttpInteraction.
     *
     * @param ctx context to receive the response
     * @param req request to process
     */
    public NettyHttpInteraction(ChannelHandlerContext ctx, HttpRequest req) {
      this.committed = false;
      this.ctx = ctx;
      this.req = req;
    }

    @Override
    public boolean isCommitted() {
      return committed;
    }

    @Override
    public String getRemoteAddr() {
      return ((InetSocketAddress)ctx.channel().remoteAddress()).
             getAddress().getHostAddress();
    }

    @Override
    public Optional<String> getQueryString() {
      try {
        return Optional.ofNullable(new URL(req.getUri()).getQuery());
      } catch (MalformedURLException e) {
        return Optional.ofNullable(null);
      }
    }

    @Override
    public String getRequestURI() {
      return(req.getUri());
    }

    @Override
    public String getRemoteUser() {
      QueryStringDecoder queryString = new QueryStringDecoder(req.getUri());
      List<String> p = queryString.parameters().get(UserParam.NAME);
      String user = (p == null ? null : p.get(0));
      return (new UserParam(user).getValue());
    }

    @Override
    public String getMethod() {
      return req.getMethod().name();
    }

    @Override
    public void proceed() {
      ReferenceCountUtil.retain(req);
      ctx.fireChannelRead(req);
    }

    @Override
    public void sendError(int code, String message) {
      HttpResponseStatus status = new HttpResponseStatus(code, message);
      sendResponseAndClose(ctx, new DefaultHttpResponse(HTTP_1_1, status));
      this.committed = true;
    }
  }
}
