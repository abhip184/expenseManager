$(document).ready(function(){
    $('.sidenav').sidenav();
  
    var userId;
        $('#signUpForm').on('submit', function(){
          var email = $('#email').val();
          var password = $('#password').val();
          var firstName = $('#first_name').val();
          var lastName = $('#last_name').val();
            $.ajax({
              type: 'POST',
              url: 'users/signup',
              data:{email: email, password:password, firstName:firstName, lastName,lastName},
              success: function (data) {
                Cookies.set('token',data.token);
                Cookies.set('firstName', data.firstName);
  
                console.log(data.userId)
                userId = data.userId;
                console.log("userid is" + userId);
                M.toast({ html: data.message })
                $('#signUpRow').addClass("hide")
                $('#userGreting').val(firstName)
                $('#defaultAccountRow').removeClass("hide")
                console.log(data)
                return false
              },
              error:function (xhr, ajaxOptions, thrownError, data){
                if(xhr.status>=300) {
                  var data = JSON.parse(xhr.responseText);
                  M.toast({ html: data.message })
                }
            }
            });
      
           return false;
      
        });
  
        $('#defaultAccountForm').on('submit', function(){
          var name = $('#account_name').val();
          var amount = $('#account_amount').val();
            $.ajax({
              type: 'POST',
              url: 'accounts',
              data:{accountName:name, currentBalance:amount, owner:userId},
              success: function (data) {
                M.toast({ html: data.message })
                window.location.href= "/accounts";
              },
              error:function (xhr, ajaxOptions, thrownError, data){
                if(xhr.status>=300) {
                  var data = JSON.parse(xhr.responseText);
                  M.toast({ html: data.message })
                }
            }
            });
      
           return false;
      
        });
      });