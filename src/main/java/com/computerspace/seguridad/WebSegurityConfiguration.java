package com.computerspace.seguridad;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class WebSegurityConfiguration extends WebSecurityConfigurerAdapter{
	@Autowired
	private AccessDeniedHandler accessDeniedHandler;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.csrf().disable()
			.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers("/admin/**").hasAnyRole("ADMIN")
			.antMatchers("/desarrolo/**").hasAnyRole("DESARROLLO")
			.antMatchers("/marketing/**").hasAnyRole("MARKETING")
			.anyRequest().authenticated()
			.and()
			.formLogin()
			//.loginPage("/login")
			.permitAll()
			.and()
			.logout()
			.permitAll().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/")
			.and()
			.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth)throws Exception{
		
		BCryptPasswordEncoder encoder = passwordEncoder();
		auth.inMemoryAuthentication()
			.withUser("des").password(encoder.encode("des")).roles("DESARROLLO")
			.and()
			.withUser("mar").password(encoder.encode("mar")).roles("MARKETING")
			.and()
			.withUser("admin").password(encoder.encode("admin")).roles("ADMIN");
	}
	
	@Bean
	public BCryptPasswordEncoder	passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	
}
