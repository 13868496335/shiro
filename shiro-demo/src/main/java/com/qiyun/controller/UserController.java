package com.qiyun.controller;

import com.qiyun.Entry.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import org.apache.shiro.subject.*;

import javax.servlet.http.HttpServletRequest;

/**
 * @Author by double.
 * @Date: 22:32
 * @remarks:
 */
@Controller
public class UserController {

    @RequestMapping(value = "/a",method = RequestMethod.GET)
    public  String  loginUrl(){
        return "login";
    }




    @RequestMapping(value = "/login",method = RequestMethod.POST,
            produces = "application/json;charset=utf-8")
    @ResponseBody
    public  String  login(User user, HttpServletRequest request){
        Subject subject = SecurityUtils.getSubject();
        String username = user.getName();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(user.getName(),user.getPassword());

    try {
            subject.login(usernamePasswordToken);
        }catch(UnknownAccountException uae){
        System.out.println("对用户[" + username + "]进行登录验证..验证未通过,未知账户");
        request.setAttribute("message_login", "未知账户");
    }catch(IncorrectCredentialsException ice){
        System.out.println("对用户[" + username + "]进行登录验证..验证未通过,错误的凭证");
        request.setAttribute("message_login", "密码不正确");
    }catch(LockedAccountException lae){
        System.out.println("对用户[" + username + "]进行登录验证..验证未通过,账户已锁定");
        request.setAttribute("message_login", "账户已锁定");
    }catch(ExcessiveAttemptsException eae){
        System.out.println("对用户[" + username + "]进行登录验证..验证未通过,错误次数过多");
        request.setAttribute("message_login", "用户名或密码错误次数过多");
    }catch(AuthenticationException ae){
        //通过处理Shiro的运行时AuthenticationException就可以控制用户登录失败或密码错误时的情景
        System.out.println("对用户[" + username + "]进行登录验证..验证未通过,堆栈轨迹如下");
        ae.printStackTrace();
        request.setAttribute("message_login", "用户名或密码不正确");
    }

        return "";
    }
}
