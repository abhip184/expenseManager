$(document).ready(function () {
    $('.sidenav').sidenav();
  
        $('#loginForm').on('submit', function () {
          var email = $('#email').val();
          var password = $('#password').val();
          console.log(email)
          console.log(password)
          $.ajax({
            type: 'POST',
            url: 'users/login',
            data: {email:email, password:password},
            success: function (data) {
              Cookies.set('token', data.token);
                Cookies.set('firstName', data.firstName);
              M.toast({ html: data.message })
              window.location.href= "/accounts";
            },
            error: function (xhr, ajaxOptions, thrownError, data) {
              if (xhr.status >= 300) {
                var data = JSON.parse(xhr.responseText);
                M.toast({ html: data.message })
              }
              return false;
            }
          });
          return false;
  
        });
      });