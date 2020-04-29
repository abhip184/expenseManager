 //Ajax and material scripts
  $(document).ready(function () {
    // material scripts 
    $('.modal').modal();
    $('.tooltipped').tooltip();
    $('.dropdown-trigger').dropdown({
      constrainWidth: false
    });
    $('.fixed-action-btn').floatingActionButton();
    $('.sidenav').sidenav();

    //setting up user introduction at navbar from cookie pushed at login time

    var userIntro = Cookies.get('firstName')
    console.log(userIntro)
    $('#userIntro').text("Hello " + userIntro)

    // idHolder to hold the id of account which is clicked for any action from dropdown structure

    var idHolder;
    $(".idHolder").on('click', function () {
      idHolder = $(this).attr('id')
      console.log(idHolder)
    })

    
    //Handling delete account request

    $('#deleteButton').click(function () {
      $.ajax({
        type: 'DELETE',
        url: '/accounts/' + idHolder,
        success: function (data) {
          $('.modal').modal('close');
          M.toast({
            html: data.message
          })
          $('#' + idHolder).parent().parent().parent().parent().fadeOut();
          location.reload()
        },
        error: function (xhr, ajaxOptions, thrownError, data) {
          if (xhr.status >= 300) {
            var data = JSON.parse(xhr.responseText);
            M.toast({
              html: data.err
            })
          }
          return false;
        }
      });
    })


    //Handling Edit account name 

    $('#editAccountNameForm').on('submit', function () {
      var newName = $('#newName').val();
      var accountId = idHolder;
      console.log(accountId);

      if(!newName.trim())
      {
        M.toast({ html: "Enter Valid Name" })
        return false
      }
      $.ajax({
        type: 'PATCH',
        url: '/accounts/' + accountId,
        // data: JSON.stringify([{"propName":"accountName","value":newName}]),
        data: {
          data: JSON.stringify([{
            propName: "accountName",
            value: newName
          }])
        },
        success: function (data) {
          $('.modal').modal('close');
          M.toast({
            html: data.message
          })
          location.reload()
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

    //Handling add new account request 
    $('#addAccountForm').on('submit', function () {

      var name = $('#account_name').val();
      var amount = $('#account_amount').val();

      if(!name.trim())
      {
        M.toast({ html: "Enter Valid Name" })
        return false
      }
      $.ajax({
        type: 'POST',
        url: '/accounts',
        data: {
          accountName: name,
          currentBalance: amount,
        },
        success: function (data) {
          M.toast({
            html: data.message
          })
          location.reload();
        },
        error: function (xhr, ajaxOptions, thrownError, data) {
          if (xhr.status >= 400) {
            var data = JSON.parse(xhr.responseText);
            M.toast({
              html: data.message
            })
          }
          return false;
        }
      });
      return false;
    });
  });

 
  $(window).load(function() {
      // Animate loader off screen
  $(".progress").fadeOut("slow");
  
 
  });