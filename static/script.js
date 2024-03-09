$(".signup-form").hide();
$(".signup").css("background", "#A59F9F");

$(".login").click(function(){
    $(".signup-form").hide();
    $(".login-form").show();
    $(".signup").css("background", "#A59F9F");
    $(".login").css("background", "#fff");
});

$(".signup").click(function(){
    $(".login-form").hide();
    $(".signup-form").show();
    $(".login").css("background", "#A59F9F");
    $(".signup").css("background", "#fff");
});

function myFunction() {
  var x = document.getElementById("login_password");
  if (x.type === "password") {
    x.type = "text";
  } else {
    x.type = "password";
  }
}

//$(".btn").click(function(){
//    $(".input").val("");
//});