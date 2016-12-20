var myApp = angular.module('myApp', []);
myApp.controller('AppCtrl', ['$scope', '$http', function($scope, $http) {
    console.log("Hello World from controller");

// myApp.service('authInterceptor', function($q) {
//   var service = this;
//   service.responseError = function(response) {
//     if (response.status == 401) {
//       window.location = "/login";
//     }
//     return $q.reject(response);
//   };
// });
// myApp.config(['$httpProvider', function($httpProvider){
//   $httpProvider.interceptors.push('authInterceptor');
// }]);

var refresh = function() {
  $http.get('/userlist').success(function(response) {
    console.log("I got the data I requested");
    $scope.userlist = response;
    $scope.user = "";
  });
};

refresh();

$scope.addUser = function() {
  console.log($scope.user);
  $http.post('/userlist', $scope.user).success(function(response) {
    console.log(response);
    refresh();
  });
};

$scope.remove = function(id) {
  console.log(id);
  $http.delete('/userlist/' + id).success(function(response) {
    refresh();
  });
};

$scope.edit = function(id) {
  console.log(id);
  $http.get('/userlist/' + id).success(function(response) {
    $scope.user = response;
  });
};  

$scope.update = function() {
  console.log($scope.user._id);
  $http.put('/userlist/' + $scope.user._id, $scope.user).success(function(response) {
    refresh();
  })
};

$scope.deselect = function() {
  $scope.user = "";
}

}]);﻿