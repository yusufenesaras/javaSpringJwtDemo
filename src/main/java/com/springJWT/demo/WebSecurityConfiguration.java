package com.springJWT.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.springJWT.demo.auth.JwtTokenFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter{
	
	@Autowired
    private JwtTokenFilter jwtTokenFilter;
	
	@Autowired
	private UserDetailsService userDetailService;
	
	@Autowired
	public void configurePasswordEncoder(AuthenticationManagerBuilder builder) throws Exception{
		builder.userDetailsService(userDetailService).passwordEncoder(getBCryptPasswordEncoder());
	}
	
	@Autowired
	public AuthenticationManager getAuthenticationManager() throws Exception{
		return super.authenticationManagerBean();
	}
	
	@Bean
	BCryptPasswordEncoder getBCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	  @Bean
	    protected void configure(HttpSecurity http) throws Exception {
	        http.csrf().disable()
	                .authorizeRequests().antMatchers("/login").permitAll()
	                .anyRequest().authenticated()
	                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

	        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
	    }
}
