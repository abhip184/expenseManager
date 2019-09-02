 // Ajax and material scripts for viewAccount ejs
 $(document).ready(function () {
     // material scripts 
     $('.modal').modal();
     $('.tooltipped').tooltip();
     $('.dropdown-trigger').dropdown({
         constrainWidth: false
     });
     $('select').formSelect();
     $('.fixed-action-btn').floatingActionButton();
     $('.sidenav').sidenav();

     var userIntro = Cookies.get('firstName')
console.log(userIntro)
$('#userIntro').text("Hello " + userIntro)

     // global from cookies and hidden fields
     const accountId = $('#accountId').val()
     console.log(accountId);
     const mode = $('#mode').val()
     console.log(mode)

     // id holder to edit delete transections
     var idHolder;
     $(".idHolder").on('click', function () {
         idHolder = $(this).attr('id')
         console.log("id holder" + idHolder)
     })

     //Handling delete transection
     $('#deleteButton').click(function () {
         $.ajax({
             type: 'DELETE',
             url: '/transections/' + idHolder,
             success: function (data) {
                 $('.modal').modal('close');
                 console.log(data)
                 M.toast({
                     html: data.message
                 })
                 // $('#' + idHolder).parent().parent().parent().fadeOut();
                 location.reload()
             },
             error: function (xhr, ajaxOptions, thrownError, data) {
                 if (xhr.status >= 400) {
                     var data = JSON.parse(xhr.responseText);
                     M.toast({
                         html: data.err
                     })
                 }
             }
         });
     })


     //handling edit transection
     $('#editTransectionForm').on('submit', function (e) {
         e.preventDefault();

         const newCategory = $('#newCategory').val()
         const newAmount = $('#newAmount').val()

         $.ajax({
             type: 'PATCH',
             url: '/transections/' + idHolder,
             data: {
                 data: JSON.stringify([{
                     "propName": "amount",
                     "value": newAmount
                 }, {
                     "propName": "category",
                     "value": newCategory
                 }, {
                     "propName": "atDate",
                     "value": new Date()
                 }])
             },
             success: function (data) {
                 $('.modal').modal('close');
                 console.log(data)
                 M.toast({
                     html: "transection saved"
                 })
                 location.reload()
             },
             error: function (xhr, ajaxOptions, thrownError, data) {
                 if (xhr.status >= 400) {
                     var data = JSON.parse(xhr.responseText);
                     M.toast({
                         html: data.err
                     })
                 }
                 return false
             }
         });
     });


     //getting updated balance  when document is ready
     $.ajax({
         type: 'GET',
         url: '/transections/balance/' + accountId,

         success: function (data) {
             console.log(data)
             $("#balanceHolder").text(data.balance + " Rs.")
             M.toast({
                 html: "Balance Updated " + data.balance,displayLength:1300
             })
         },
         error: function (xhr, ajaxOptions, thrownError, data) {
             if (xhr.status >= 400) {
                 var data = JSON.parse(xhr.responseText);
                 M.toast({
                     html: data.err
                 })
             }
         }
     });



     //Add transection 

     $('#addTransectionForm').on('submit', function () {
         const category = $('#category').val()
         const ownerId = $('#ownerId').val()


         const amount = $('#amount').val()
         var transectionType = $("input[name='transectionType']:checked").val();
         const fromAccount = $("#fromAccount").val();


         if (mode == "transfer") {


             // adding transfer type transections
             $.ajax({
                 type: 'POST',
                 url: '/transections',
                 data: {
                     to: ownerId,
                     category: category,
                     toAccount: accountId,
                     fromAccount: fromAccount,
                     type: "transfer",
                     amount: amount
                 },
                 success: function (data) {
                     $('.modal').modal('close');
                     console.log(data)
                     M.toast({
                         html: "transfer saved"
                     })
                     return false
                     // location.reload()
                 }, 
                 error: function (xhr, ajaxOptions, thrownError, data) {
                     if (xhr.status >= 400) {
                         var data = JSON.parse(xhr.responseText);
                         M.toast({
                             html: data.err
                         })
                     }
                     return false
                 }
             });
         } else {
             // adding income expense type transections
             $.ajax({
                 type: 'POST',
                 url: '/transections',
                 data: {
                     category: category,
                     accountId: accountId,
                     type: transectionType,
                     amount: amount
                 },
                 success: function (data) {
                     $('.modal').modal('close');
                     console.log(data)
                     M.toast({
                         html: "transection saved"
                     })
                     location.reload()
                 },
                 error: function (xhr, ajaxOptions, thrownError, data) {
                     if (xhr.status >= 400) {
                         var data = JSON.parse(xhr.responseText);
                         M.toast({
                             html: data.err
                         })
                     }
                 }
             });

         }

     });

     //Handling Add friend from
     $('#addFriendForm').on('submit', function () {
         var friendEmail = $('#friendEmail').val()
         $.ajax({
             type: 'PATCH',
             url: '/accounts/addFriend/' + accountId,
             data: {
                 friendEmail: friendEmail
             },
             success: function (data) {
                 $('.modal').modal('close');
                 console.log(data)
                 M.toast({
                     html: data.message
                 })
                 location.reload()
             },
             error: function (xhr, ajaxOptions, thrownError, data) {
                 if (xhr.status >= 400) {
                     var data = JSON.parse(xhr.responseText);
                     M.toast({
                         html: data.message
                     })
                     return false
                 }
             }

         });
     })
 })
 $(window).load(function() {
 // Animate loader off screen
 $(".progress").fadeOut("slow");;
});