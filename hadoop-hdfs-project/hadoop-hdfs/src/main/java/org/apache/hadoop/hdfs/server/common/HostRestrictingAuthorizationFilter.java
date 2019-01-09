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
package org.apache.hadoop.hdfs.server.common;

import javax.servlet.ServletException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.web.AuthFilter;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.apache.hadoop.hdfs.web.WebHdfsFileSystem;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Enumeration;
import java.lang.Iterable;
import java.util.Iterator;
import java.util.Map;
import java.util.Collections;
import java.util.HashMap;
import java.util.Optional;
import java.util.function.Predicate;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.io.FilenameUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HostRestrictingAuthorizationFilter implements Filter {
  private Logger LOG = LoggerFactory.getLogger(HostRestrictingAuthorizationFilter.class);
  private HashMap<String, ArrayList<Rule>> RULEMAP = null;
  public static final String HDFS_CONFIG_PREFIX = "dfs.web.authentication.";
  public static final String RESTRICTION_CONFIG = "host.allow.rules";
  // A Java Predicate for query string parameters on which to filter requests
  public static final Predicate<String> restrictedOperations = qStr -> (qStr.trim().equalsIgnoreCase("op=OPEN") ||
                                                                        qStr.trim().equalsIgnoreCase("op=GETDELEGATIONTOKEN"));

  private class Rule {
    private final SubnetUtils.SubnetInfo subnet;
    private final String path;

    /*
     * A class for holding dropbox filter rules
     *
     * @param subnet - the IPv4 subnet for which this rule is valid (pass null for
     * any network location)
     *
     * @param path - the HDFS path for which this rule is valid
     */
    Rule(SubnetUtils.SubnetInfo subnet, String path) {
      this.subnet = subnet;
      this.path = path;
    }

    public SubnetUtils.SubnetInfo getSubnet() {
      return(subnet);
    }

    public String getPath() {
      return(path);
    }
  }

  /*
   * Check all rules for this user to see if one matches for this host/path pair
   *
   * @Param: user - user to check rules for
   *
   * @Param: host - IP address (e.g. "192.168.0.1")
   *
   * @Param: path - file path with no scheme (e.g. /path/foo)
   *
   * @Returns: true if a rule matches this user, host, path tuple false if an
   * error occurs or no match
   */
  private boolean matchRule(String user, String remoteIp, String path) {
    // allow lookups for blank in the rules for user and path
    user = (user == null ? "" : user);
    path = (path == null ? "" : path);

    ArrayList<Rule> userRules = RULEMAP.get(user);
    ArrayList<Rule> anyRules = RULEMAP.get("*");
    if(anyRules != null) {
      if(userRules != null) {
        userRules.addAll(RULEMAP.get("*"));
      } else {
        userRules = anyRules;
      }
    }

    LOG.trace("Got user: {}, remoteIp: {}, path: {}", user, remoteIp, path);

    // isInRange fails for null/blank IPs, require an IP to approve
    if(remoteIp == null) {
      LOG.trace("Returned false due to null rempteIp");
      return false;
    }

    if(userRules != null) {
      for(Rule rule : userRules) {
        LOG.trace("Evaluating rule, subnet: {}, path: {}",
                  rule.getSubnet() != null ? rule.getSubnet().getCidrSignature() : null, rule.getPath());
        try {
          if((rule.getSubnet() == null || rule.getSubnet().isInRange(remoteIp))
              && FilenameUtils.directoryContains(WebHdfsFileSystem.PATH_PREFIX + rule.getPath(), path)) {
            LOG.debug("Found matching rule, subnet: {}, path: {}; returned true",
                      rule.getSubnet() != null ? rule.getSubnet().getCidrSignature() : null, rule.getPath());
            return true;
          }
        } catch(IOException e) {
          LOG.warn("Got IOException {}; returned false", e);
          return false;
        }
      }
    }
    LOG.trace("Found no rules for user");
    return false;
  }

  @Override
  public void destroy() {
    RULEMAP = null;
  }

  @Override
  public void init(FilterConfig config) throws ServletException {
    HashMap<String, String> overrideConfigs = new HashMap<String, String>();

    // Process dropbox rules
    String dropboxRules = config.getInitParameter(RESTRICTION_CONFIG);
    if(dropboxRules != null) {
      // name: dropbox.allow.rules
      // value: user1,network/bits1,path_glob1|user2,network/bints2,path_glob2...
      String[] rules = dropboxRules.split("\\||\n");
      RULEMAP = new HashMap<String, ArrayList<Rule>>(rules.length);
      for(String line : rules) {
        String[] parts = line.split(",", 3);
        LOG.debug("Loaded rule: user: " + parts[0] + " network/bits: " + parts[1] + " path: " + parts[2]);
        String globPattern = parts[2];
        // Map is {"user": [subnet, path]}
        Rule rule = null;
        if(parts[1].trim().equals("*")) {
          rule = new Rule(null, globPattern);
        } else {
          rule = new Rule(new SubnetUtils(parts[1]).getInfo(), globPattern);
        }
        // Update the rule map with this rule
        ArrayList<Rule> ruleList = RULEMAP.getOrDefault(parts[0], new ArrayList<Rule>() {});
        ruleList.add(rule);
        RULEMAP.put(parts[0], ruleList);
      }
    } else {
      // make an empty hash since we have no rules
      RULEMAP = new HashMap(0);
    }
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws IOException, ServletException {
    final HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;

    final String address = request.getRemoteAddr();
    final String user = httpRequest.getRemoteUser();
    final String uri = httpRequest.getRequestURI();
    final Optional<String> query = Optional.ofNullable(httpRequest.getQueryString());

    if(!response.isCommitted() && "GET".equalsIgnoreCase(httpRequest.getMethod())) {
      boolean readQuery = query.map((q) -> Arrays.stream(q.trim().split("&")).anyMatch(restrictedOperations)).orElse(true);
      if (readQuery && !(matchRule("*", address, uri) || matchRule(user, address, uri))) {
        httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
          "WebHDFS is configured write-only for " + user + "@" + address);
      }
    }

    filterChain.doFilter(request, response);
  }

  /**
   * Constructs a mapping of configuration properties to be used for filter
   * initialization.  The mapping includes all properties that start with the
   * specified configuration prefix.  Property names in the mapping are trimmed
   * to remove the configuration prefix.
   *
   * @param conf configuration to read
   * @param confPrefix configuration prefix
   * @return mapping of configuration properties to be used for filter
   *     initialization
   */
  public static Map<String, String> getFilterParams(Configuration conf,
      String confPrefix) {
    return conf.getPropsWithPrefix(confPrefix);
  }

  /**
   * Defines the minimal API requirements for the filter to execute its
   * filtering logic.  This interface exists to facilitate integration in
   * components that do not run within a servlet container and therefore cannot
   * rely on a servlet container to dispatch to the {@link #doFilter} method.
   * Applications that do run inside a servlet container will not need to write
   * code that uses this interface.  Instead, they can use typical servlet
   * container configuration mechanisms to insert the filter.
   */
  public interface HttpInteraction {

    /**
     * Returns if the request has been committed.
     *
     * @return boolean
     */
    boolean isCommitted();

    /**
     * Returns the value of the requesting client address.
     *
     * @return the remote address
     */
    String getRemoteAddr();

    /**
     * Returns the user ID making the request.
     *
     * @return the user
     */
    String getRemoteUser();

    /**
     * Returns the value of the request URI.
     *
     * @return the request URI
     */
    String getRequestURI();

    /**
     * Returns the value of the query string.
     *
     * @return an optional contianing the URL query string
     */
    Optional<String> getQueryString();

    /**
     * Returns the method.
     *
     * @return method
     */
    String getMethod();

    /**
     * Called by the filter after it decides that the request may proceed.
     *
     * @throws IOException if there is an I/O error
     * @throws ServletException if the implementation relies on the servlet API
     *     and a servlet API call has failed
     */
    void proceed() throws IOException, ServletException;

    /**
     * Called by the filter after it decides that the request is an
     * unauthorized request and therefore must be rejected.
     *
     * @param code status code to send
     * @param message response message
     * @throws IOException if there is an I/O error
     */
    void sendError(int code, String message) throws IOException;
  }
}
