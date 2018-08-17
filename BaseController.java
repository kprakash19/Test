package com.rogers.controller;

import akka.util.ByteString$;
import akka.util.ByteStringBuilder;
import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rogers.annotation.ClassPreamble;
import com.rogers.annotation.Complexity;
import com.rogers.constants.RogersConstants;
import com.rogers.logging.mdc.MDContext;
import com.rogers.models.CookieVO;
import play.http.HttpEntity;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.ResponseHeader;
import play.mvc.Result;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@ClassPreamble(description = "BaseController extends controllers and have few more methods", date = "16-05-2018")
@Complexity(Complexity.ComplexityLevel.COMPLEX)
public abstract class BaseController extends Controller {

    public static List<CookieVO> buildCookiesVOFromMap(Map<String, String> cookies) {
        return cookies.entrySet().stream().map(
                cookieNameValue -> new CookieVO(cookieNameValue.getKey(), cookieNameValue.getValue())
        ).collect(Collectors.toList());
    }

    public static List<Http.Cookie> buildHTTPCookiesFromVO(List<CookieVO> cookies) {
        return cookies.stream().map(
                cookie -> {
                    final Http.CookieBuilder cookieBuilder = Http.Cookie.
                            builder(cookie.name(), cookie.value()).
                            withPath(cookie.path()).
                            withDomain(cookie.domain()).
                            withSecure(cookie.secure()).
                            withHttpOnly(cookie.httpOnly());
                    cookie.sameSite().
                            ifPresent(sameSite -> cookieBuilder.withSameSite(Http.Cookie.SameSite.parse(sameSite.value()).get()));
                    return cookieBuilder.build();
                }).collect(Collectors.toList());
    }


    public static Result ok(String content, List<CookieVO> cookies) {
        return status(Http.Status.OK, content, cookies);
    }

    public static Result ok(String content, Map<String, String> cookies) {
        return status(Http.Status.OK, content, cookies);
    }

    public static Result ok(JsonNode content, Map<String, String> cookies) {
        return status(Http.Status.OK, content, cookies);
    }

    public static Result ok(JsonNode content, List<CookieVO> cookies) {
        return status(Http.Status.OK, content, cookies);
    }


    public static Result status(int status, String content, Map<String, String> cookies) {
        return status(status, content, buildCookiesVOFromMap(cookies));
    }

    public static Result status(int status, String content, List<CookieVO> cookies) {
        return status(buildHTTPCookiesFromVO(cookies), new ResponseHeader(status, Collections.emptyMap(), (String) null), HttpEntity.fromString(content, "utf-8"),
                session(), flash());
    }

    public static Result status(int status, JsonNode content, Map<String, String> cookies) {
        return status(status, content, buildCookiesVOFromMap(cookies));
    }

    public static Result status(int status, JsonNode content, List<CookieVO> cookies) {
        return status(buildHTTPCookiesFromVO(cookies), new ResponseHeader(status, Collections.emptyMap(), (String) null), buildJson(content, JsonEncoding.UTF8), session(), flash());
    }

    public static Result status(List<Http.Cookie> httpCookies, ResponseHeader responseHeader, HttpEntity httpEntity, Http.Session session, Http.Flash flash) {
        return buildResult(httpCookies, responseHeader, httpEntity, session, flash);
    }


    private static Result buildResult(List<Http.Cookie> httpCookies, ResponseHeader responseHeader, HttpEntity httpEntity, Http.Session session, Http.Flash flash) {
        return new Result(responseHeader, httpEntity, session, flash, httpCookies);
    }

    public static HttpEntity buildJson(JsonNode json, JsonEncoding encoding) {
        if (json == null) {
            throw new NullPointerException("Null content");
        }

        ObjectMapper mapper = Json.mapper();
        ByteStringBuilder builder = ByteString$.MODULE$.newBuilder();

        try {
            JsonGenerator jgen = mapper.getFactory().createGenerator(builder.asOutputStream(), encoding);

            mapper.writeValue(jgen, json);
            String contentType = Http.MimeTypes.JSON;
            return new HttpEntity.Strict(builder.result(), Optional.of(contentType));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    /*
    * Method return http context
    * */
    public Object getRequestObject(){
        return Http.Context.current().args.get(RogersConstants.REQUEST_OBJECT);
    }

    public MDContext getMDContext(){
        return (MDContext) Http.Context.current().args.get(RogersConstants.LOGGER_PROCESSING);
    }

}
