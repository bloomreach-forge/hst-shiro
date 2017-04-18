<%@ include file="/WEB-INF/jsp/include/imports.jsp" %>

<hst:setBundle basename="essentials.homepage"/>
<div>
  <h1><fmt:message key="homepage.title" var="title"/><c:out value="${title}"/></h1>
  <p><fmt:message key="homepage.text" var="text"/><c:out value="${text}"/></p>
  <c:if test="${!hstRequest.requestContext.cmsRequest}">
    <p>
      [This text can be edited <a href="http://localhost:8080/cms/?1&path=/content/documents/administration/labels/homepage" target="_blank">here</a>.]
    </p>
  </c:if>
</div>
<hst:include ref="container"/>

<hr/>

<h3>Checking Authentication Status using Shiro Tag Libraries</h3>

<shiro:authenticated>
  <p>Visit your <a href="<hst:link path="/events"/>">Events page</a>.</p>
</shiro:authenticated>
<shiro:notAuthenticated>
  <p>
    <strong>Note:</strong> If you want to access the authenticated-only 
    <a href="<hst:link path="/events"/>">Events page</a>,
    you will need to log-in first.
  </p>
</shiro:notAuthenticated>

<hr/>

<h3>Role checks using Shiro Tag Libraries</h3>

<p>Roles you have:</p>
<ul>
  <shiro:hasRole name="everybody"><li>everybody</li></shiro:hasRole>
  <shiro:hasRole name="author"><li>author</li></shiro:hasRole>
  <shiro:hasRole name="editor"><li>editor</li></shiro:hasRole>
  <shiro:hasRole name="admin"><li>admin</li></shiro:hasRole>
</ul>

<p>Roles you DON'T have:</p>
<ul>
  <shiro:lacksRole name="everybody"><li>everybody</li></shiro:lacksRole>
  <shiro:lacksRole name="author"><li>author</li></shiro:lacksRole>
  <shiro:lacksRole name="editor"><li>editor</li></shiro:lacksRole>
  <shiro:lacksRole name="admin"><li>admin</li></shiro:lacksRole>
</ul>

<hr/>

<h3>Role checks uing <code>HttpServletRequest#isUserInRole(String)</code></h3>

<p>Roles you have:</p>
<ul>
  <% if (request.isUserInRole("everybody")) { %><li>everybody</li><% } %>
  <% if (request.isUserInRole("author")) { %><li>author</li><% } %>
  <% if (request.isUserInRole("editor")) { %><li>editor</li><% } %>
  <% if (request.isUserInRole("admin")) { %><li>admin</li><% } %>
</ul>

<p>Roles you DON'T have:</p>
<ul>
  <% if (!request.isUserInRole("everybody")) { %><li>everybody</li><% } %>
  <% if (!request.isUserInRole("author")) { %><li>author</li><% } %>
  <% if (!request.isUserInRole("editor")) { %><li>editor</li><% } %>
  <% if (!request.isUserInRole("admin")) { %><li>admin</li><% } %>
</ul>

<h3>Permissions</h3>
<ul>

  <shiro:lacksPermission name="hippodocuments:author"><li>You may <strong>NOT</strong> author documents!</li></shiro:lacksPermission>
  <shiro:hasPermission name="hippodocuments:author"><li>You may author documents!</li></shiro:hasPermission>

  <shiro:lacksPermission name="hippodocuments:editor"><li>You may <strong>NOT</strong> edit documents!</li></shiro:lacksPermission>
  <shiro:hasPermission name="hippodocuments:editor"><li>You may edit documents!</li></shiro:hasPermission>

  <shiro:lacksPermission name="everywhere:admin"><li>You may <strong>NOT</strong> administer everywhere!</li></shiro:lacksPermission>
  <shiro:hasPermission name="everywhere:admin"><li>You may administer everywhere!</li></shiro:hasPermission>

</ul>
