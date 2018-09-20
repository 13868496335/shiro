package com.qiyun.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * @Created by double.
 * @Date: 2018/9/14
 * @remarks:
 *     自定义Realm 认证器,需要继承  AuthorizingRealm
 */
public class CustomRealm extends AuthorizingRealm {

    {
        super.setName("customRealm");
    }
    /**
     * 授权，功能权限
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        String  username  = (String) principalCollection.getPrimaryPrincipal();//获取角色信息
        Set<String> roles =  getRoleByUsername(username); //根据用户名获取角色
        Set<String> rolePermissions =  getRolePermissions(username); //根据用户名获取数据权限
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();//授权
        simpleAuthorizationInfo.addStringPermissions(rolePermissions);
        simpleAuthorizationInfo.addRoles(roles);
        return simpleAuthorizationInfo;//返回授权信息
    }

    private Set<String> getRolePermissions(String username) {
        Set<String> rolePermissions = new HashSet<>();
        rolePermissions.add("admin:select");
        rolePermissions.add("user:select");
        return  rolePermissions;
    }

    private Set<String> getRoleByUsername(String username) {
        Set<String> roles = new HashSet<>();
        roles.add("admin");
        roles.add("user");
        return  roles;
    }







    /**
     * 认证 账号密码
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {


        //1.UsernamePasswordToken 传来的 ,获取用户名
        String  username = (String) authenticationToken.getPrincipal();

        //2.通过用户名，查询用户密码
        String  password = getPasswordByUsername(username);


        if(password==null&&password==""){
            return null;
        }
        System.out.println(username+"-----------"+password);
        //3.为传入的密码加密加盐，和这个真实的用户信息比对
        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(username,password,"customRealm");
        simpleAuthenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("llc"));//加盐
        return simpleAuthenticationInfo;
    }




    private String  getPasswordByUsername(String username) {

        HashMap hashMap = new HashMap();
        hashMap.put("llc","521e9069447df3a84ecd878a726b45c2");
        hashMap.put("lmx","1978e5e05bfec5f248dfbed49ef9ee3f");

        return (String) hashMap.get(username);
    }
 /*   public static  void main(String arg[]){
        Hash hash = new Md5Hash("654321","llc");
        System.out.println(hash.toString());
    }*/
}
