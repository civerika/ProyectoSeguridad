package com.computerspace.seguridad;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;



@Controller
@RequestMapping (path="/")
public class SeguridadController {

	@GetMapping
	public String login (){	
		return "login";
	}
	@GetMapping("/marketing")
	public String marketing () {
		return "marketing";
	}
	@GetMapping("/desarrolo")
	public String desarrollo () {
		return "desarrollo";
	}
	@GetMapping("/admin")
	public String admin () {
		return "admin";
	}
	@GetMapping("/403")
	public String error () {
		return "error";
	}
	@GetMapping("/logout")
	public String logout (HttpServletRequest request, HttpServletResponse response){
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null){
			new SecurityContextLogoutHandler().logout(request, response, auth);
		}
		return"redirect:/";
	}

}
