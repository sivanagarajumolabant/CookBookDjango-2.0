import mimetypes, json, re, sys, jwt, xlsxwriter, shutil
from rest_framework.decorators import api_view
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from .serializers import *
from rest_framework import status, generics
from rest_framework.response import Response
from django.http import HttpResponse
from django.conf import settings
from django.core import mail
from CookBook_Backend.settings import EMAIL_HOST_USER
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from Config.config import frontend_url, fileshare_connectionString, container_name_var, account_name, account_key


class MyObtainTokenPairView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = MyTokenObtainPairSerializer


class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        token = token.replace('?', '').strip()
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms=['HS256'])
            user = Users.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()
            return Response({'msg': 'Sucessfully Email Confirmed! Please Login'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'msg': 'Expired Please Resend Email'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'msg': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'msg': 'Token is not valid, please request a new one'},
                                status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success': True, 'msg': 'credentials valid', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'msg': 'Token is not valid, please request a new one'},
                            status=status.HTTP_401_UNAUTHORIZED)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = Resetpasswordemailserializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if Users.objects.filter(email=email).exists():
            user = Users.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            absurl = frontend_url + 'resetpassword?token=' + \
                     str(token) + "?uid=" + uidb64
            subject = 'Forgot Password'
            html_message = render_to_string(
                'forgotpassword.html', {'url': absurl})
            plain_message = strip_tags(html_message)
            from_email = EMAIL_HOST_USER
            to = user.email
            mail.send_mail(subject, plain_message, from_email,
                           [to], html_message=html_message)
            return Response({'msg': 'we have sent you a link to reset your password'},
                            status=status.HTTP_201_CREATED)
        else:
            return Response({'msg': 'No Such user Please Register'})

        return Response({'msg': 'we have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'msg': 'Password Reset Success'}, status=status.HTTP_200_OK)


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        return Response(user_data, status=status.HTTP_201_CREATED)


class ResendVerifyEmail(generics.GenericAPIView):
    serializer_class = resendemailserializer

    def post(self, request):
        user = request.data
        email = user['email']
        try:
            user = Users.objects.get(email=email)
            if user.is_verified:
                return Response({'msg': 'user is already verified'})
            token = RefreshToken.for_user(user)
            absurl = frontend_url + 'emailverification?' + str(token)
            subject = 'Verify your email'
            html_message = render_to_string('verifys.html', {'url': absurl})
            plain_message = strip_tags(html_message)
            from_email = EMAIL_HOST_USER
            to = user.email
            mail.send_mail(subject, plain_message, from_email,
                           [to], html_message=html_message)
            return Response({'msg': 'The Verification email has been sent Please Confirm'},
                            status=status.HTTP_201_CREATED)
        except:
            return Response({'msg': 'No Such user Please Register'})


@api_view(['GET', 'POST'])
def migrationcreate(request):
    project_id = request.data['Project_Version_Id']
    migration_name = request.data['Migration_Name']
    project_version_limit = request.data['Project_Version_limit']
    feature_version_limit = request.data['Feature_Version_Limit']

    serializer = migrationcreateserializer(data=request.data)
    check_migration = Migrations.objects.filter(Project_Version_Id=project_id, Migration_Name=migration_name)

    if not check_migration:
        if project_version_limit == '' and feature_version_limit == '':
            if serializer.is_valid():
                serializer.save(Project_Version_Limit=3, Feature_Version_Limit=3)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            if serializer.is_valid():
                serializer.save(Project_Version_Limit=project_version_limit,
                                Feature_Version_Limit=feature_version_limit)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response('Migration Type already exist')


@api_view(['GET', 'POST'])
def migration_names_list(request):
    migration_data = Migrations.objects.values('Migration_Name').distinct()
    final_list = []
    inter_dict = {}
    for migration in migration_data:
        inter_dict['Migration_Name'] = migration['Migration_Name']
        final_list.append(inter_dict.copy())
    return Response(final_list)


@api_view(['GET', 'POST'])
def project_versions_list(request):
    migration_name = request.data['Migration_Name']
    project_versions = Migrations.objects.filter(Migration_Name=migration_name).values(
        'Project_Version_Id').distinct()
    final_list = []
    if project_versions:
        versions_list = [dict['Project_Version_Id'] for dict in project_versions]
        inter_dict = {}
        for version in versions_list:
            inter_dict['Title'] = "V" + version
            inter_dict['Code'] = int(version)
            final_list.append(inter_dict.copy())
    return Response(final_list)


@api_view(['GET', 'POST'])
def object_type_create(request):
    project_id = request.data['Project_Version_Id']
    migration_name = request.data['Migration_Name']
    object_type_str = request.data['Object_Type_Str']

    object_type_str_list = object_type_str.split('/')

    if len(object_type_str_list) == 1:
        object_type = object_type_str_list[0]
        check_object = ObjectTypes.objects.filter(Project_Version_Id=project_id, Migration_Name=migration_name,
                                                  Object_Type=object_type)
        if check_object:
            return Response('Object Type already exist')
        else:
            ObjectTypes.objects.create(Project_Version_Id=project_id, Migration_Name=migration_name,
                                       Object_Type=object_type)
            return Response('Object Type created', status=status.HTTP_201_CREATED)
    elif len(object_type_str_list) > 1:
        object_type = object_type_str_list[-1]
        parent_object_type = object_type_str_list[-2]
        p_object = ObjectTypes.objects.get(Project_Version_Id=project_id, Migration_Name=migration_name,
                                           Object_Type=parent_object_type)
        check_object = ObjectTypes.objects.filter(Project_Version_Id=project_id, Migration_Name=migration_name,
                                                  Object_Type=object_type, Parent_Object_Id=p_object.Object_Id)
        if check_object:
            return Response('Object Type already exist')
        else:
            ObjectTypes.objects.create(Project_Version_Id=project_id, Migration_Name=migration_name,
                                       Object_Type=object_type, Parent_Object_Id=p_object.Object_Id)
            return Response('Object Type created', status=status.HTTP_201_CREATED)


@api_view(['GET', 'POST'])
def parent_object_list(request):
    project_version = request.data['Project_Version_Id']
    migration_name = request.data['Migration_Name']

    parent_objects_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=migration_name,
                                                     Parent_Object_Id='')
    final_list = []
    inter_dict = {}
    for parent in parent_objects_data.values():
        inter_dict['Parent_Object'] = parent['Object_Type']
        final_list.append(inter_dict.copy())
    return Response(final_list)


def get_child_objects(project_version, migration_name, parent_id):
    inter_dict = {}
    inter_list = []

    sub_objects_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=migration_name,
                                                  Parent_Object_Id=parent_id)
    if sub_objects_data:
        sub_objects_list = [obj['Object_Type'] for obj in sub_objects_data.values()]
        for sub_object in sub_objects_list:
            inter_dict['Object_Type'] = sub_object
            sub_object_id_data = ObjectTypes.objects.filter(Project_Version_Id=project_version,
                                                            Migration_Name=migration_name,
                                                            Object_Type=sub_object, Parent_Object_Id=parent_id)
            sub_object_id = sub_object_id_data.values()[0]['Object_Id']

            sub_inter_dict = get_child_objects(project_version, migration_name, sub_object_id)

            inter_dict['Sub_Objects'] = sub_inter_dict
            inter_list.append(inter_dict.copy())
    else:
        inter_list = []
    return inter_list


@api_view(['GET', 'POST'])
def object_types_format(request):
    project_version = request.data['Project_Version_Id']
    migration_name = request.data['Migration_Name']

    parent_objects_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=migration_name,
                                                     Parent_Object_Id='')
    parent_objects_list = [obj['Object_Type'] for obj in parent_objects_data.values()]

    final_dict = {}
    final_list = []
    for parent in parent_objects_list:
        parent_id_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=migration_name,
                                                    Object_Type=parent, Parent_Object_Id='')
        parent_id = parent_id_data.values()[0]['Object_Id']

        final_dict['Object_Type'] = parent

        inter_list = get_child_objects(project_version, migration_name, parent_id)

        final_dict['Sub_Objects'] = inter_list
        final_list.append(final_dict.copy())
    return Response(final_list)


@api_view(['GET', 'POST'])
def featurecreate(request):
    migration_name = request.data['Migration_Name']
    object_id = request.data['Object_Id']
    feature_name = request.data['Feature_Name']
    project_version = request.data['Project_Version_Id']

    check_feature = Features.objects.filter(Migration_Name=migration_name, Project_Version_Id=project_version,
                                            Object_Id=object_id, Feature_Name=feature_name)
    if check_feature:
        return Response("Feature already present with this version.Kindly request access for it")
    else:
        serializer = FeatureSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(Feature_Version_Id=int(request.data['Feature_Version_Id']) + 1)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def approval_request_create(request):
    email = request.data['User_Email']
    migration_name = request.data['Migration_Name']
    request_str = request.data['Approval_Request']
    access_type = request.data['Access_Type']

    current_approval = Approvals.objects.filter(User_Email=email, Migration_Name=migration_name,
                                                Approval_Request=request_str, Access_Type=access_type)
    if current_approval:
        return Response("Approval request already present, Please wait for admin to approve")
    else:
        serializer = ApprovalSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def create_permission_format(string_list):
    temp_dict = {}
    i = 0
    if (i + 1) < len(string_list):
        if len(string_list) - (i + 1) == 1:
            if string_list[-1] == 'All':
                temp_dict[string_list[i]] = {"Feature_Names": ["All"]}
                temp_dict[string_list[i]]["Sub_Objects"] = {"All": "All"}
            else:
                temp_dict[string_list[i]] = {"Feature_Names": [string_list[-1]]}
                temp_dict[string_list[i]]["Sub_Objects"] = {}
        else:
            temp_dict[string_list[i]] = {"Feature_Names": []}
            temp_dict[string_list[i]]["Sub_Objects"] = create_permission_format(string_list[i + 1:])
    return temp_dict


def update_permission_format(string_list, format):
    i = 0
    if (i + 1) < len(string_list):
        if string_list[0] in format.keys():
            temp_format = format[string_list[0]]['Sub_Objects']
            update_permission_format(string_list[i + 1:], temp_format)
        else:
            if len(string_list) - (i + 1) == 1:
                if string_list[-1] == 'All':
                    format[string_list[0]] = {"Feature_Names": ["All"],
                                              "Sub_Objects": {"All": "All"}}
                else:
                    format[string_list[0]] = {"Feature_Names": [string_list[-1]],
                                              "Sub_Objects": {}}
            else:
                create_format = create_permission_format(string_list[i:])
                format[string_list[0]] = create_format[string_list[0]]
    return format


@api_view(['GET', 'POST'])
def permission_create(request):
    email = request.data['User_Email']
    project_version = request.data['Project_Version_Id']
    migration_name = request.data['Migration_Name']
    approval_str = request.data['Approval_Str']
    access_type = request.data['Access_Type']

    check_object_permission = Permissions.objects.filter(User_Email=email, Migration_Name=migration_name,
                                                         Access_Type=access_type,
                                                         Parent_Object_Type=approval_str.split('/')[0])
    if check_object_permission:
        approval_str_list = approval_str.split('/')
        format_string = check_object_permission.values()[0]['Current_Permissions']
        format_string = format_string.replace("\'", "\"")
        format_dict = json.loads(format_string)
        update_dict = update_permission_format(approval_str_list, format_dict)
        permission_object = Permissions.objects.get(User_Email=email, Migration_Name=migration_name,
                                                    Access_Type=access_type,
                                                    Parent_Object_Type=approval_str_list[0])
        permission_object.Current_Permissions = update_dict
        permission_object.save()
        return Response(update_dict)
    else:
        approval_str_list = approval_str.split('/')
        format_dict = create_permission_format(approval_str_list)
        Permissions.objects.create(User_Email=email, Migration_Name=migration_name,
                                   Access_Type=access_type, Parent_Object_Type=approval_str_list[0],
                                   Current_Permissions=format_dict)
        return Response(format_dict)


def recursive_menu_creation(project_version, mig_name, parent_object_id):
    inter_dict = {}
    inter_list = []

    sub_objects_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                  Parent_Object_Id=parent_object_id)
    if sub_objects_data:
        sub_objects_list = [obj['Object_Type'] for obj in sub_objects_data.values()]
        for sub_object in sub_objects_list:
            inter_dict['Object_Type'] = sub_object
            sub_object_id_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                            Object_Type=sub_object, Parent_Object_Id=parent_object_id)
            sub_object_id = sub_object_id_data.values()[0]['Object_Id']
            inter_dict['Object_Id'] = sub_object_id

            sub_features_data = Features.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                        Object_Id=sub_object_id)
            feature_dict = {}
            feature_names_list = []

            for feature in sub_features_data.values():
                feature_dict['Feature_Name'] = feature['Feature_Name']
                feature_dict['Feature_Id'] = feature['Feature_Id']
                feature_names_list.append(feature_dict.copy())
            inter_dict['Sub_Menu'] = feature_names_list

            sub_inter_dict = recursive_menu_creation(project_version, mig_name, sub_object_id)

            inter_dict['Sub_Objects'] = sub_inter_dict
            inter_list.append(inter_dict.copy())
    else:
        inter_list = []
    return inter_list


@api_view(['GET', 'POST'])
def menu_view_creation(request):
    email = request.data['User_Email']
    mig_name = request.data['Migration_Name']
    project_version = request.data['Project_Version_Id']

    parent_objects_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                     Parent_Object_Id='')
    parent_objects_list = [obj['Object_Type'] for obj in parent_objects_data.values()]

    final_dict = {}
    final_list = []

    for object_type in parent_objects_list:

        object_id_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                    Object_Type=object_type, Parent_Object_Id='')
        object_id = object_id_data.values()[0]['Object_Id']

        final_dict['Object_Type'] = object_type
        final_dict['Object_Id'] = object_id

        features_data = Features.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                Object_Id=object_id)
        feature_dict = {}
        feature_names_list = []

        for feature in features_data.values():
            feature_dict['Feature_Name'] = feature['Feature_Name']
            feature_dict['Feature_Id'] = feature['Feature_Id']
            feature_names_list.append(feature_dict.copy())

        final_dict['Sub_Menu'] = feature_names_list

        inter_list = recursive_menu_creation(project_version, mig_name, object_id)

        final_dict['Sub_Objects'] = inter_list
        final_list.append(final_dict.copy())
    return Response(final_list)


@api_view(['GET', 'POST'])
def features_list(request):
    mig_name = request.data['Migration_Name']
    project_version = request.data['Project_Version_Id']
    object_types_str = request.data['Object_Type_String']

    object_type = object_types_str.split('/')[-1]

    object_id_data = ObjectTypes.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                                Object_Type=object_type)
    object_id = object_id_data.values()[0]['Object_Id']

    features_data = Features.objects.filter(Project_Version_Id=project_version, Migration_Name=mig_name,
                                            Object_Id=object_id)
    feature_dict = {}
    feature_names_list = []

    for feature in features_data.values():
        feature_dict['Feature_Name'] = feature['Feature_Name']
        feature_names_list.append(feature_dict.copy())

    return Response(feature_names_list)


def check_permission(string_list, format):
    flag = False
    i = 0
    if (i + 1) < len(string_list[:-1]):
        if string_list[0] in format.keys():
            sub_object_string = format[string_list[0]]['Sub_Objects']
            sub_object_string = sub_object_string.replace("\'", "\"")
            sub_object_format = json.loads(sub_object_string)
            if 'ALL' in sub_object_format.keys():
                flag = True
            else:
                check_permission(string_list[i + 1:], sub_object_format)
    else:
        if string_list[0] in format.keys():
            feature_list = format[string_list[0]]['Feature_Names']
            if 'ALL' in feature_list:
                flag = True
            elif string_list[-1] in feature_list:
                flag = True
    return flag


@api_view(['GET', 'POST'])
def check_user_access(request):
    email = request.data['User_Email']
    mig_name = request.data['Migration_Name']
    object_types_str = request.data['Object_Type_String']

    string_list = object_types_str.split('/')
    parent_object = string_list[0]

    check_edit_perm = Permissions.objects.filter(User_Email=email, Migration_Name=mig_name,
                                                 Parent_Object_Type=parent_object, Access_Type='Edit')
    check_view_perm = Permissions.objects.filter(User_Email=email, Migration_Name=mig_name,
                                                 Parent_Object_Type=parent_object, Access_Type='View')
    access_status = 0
    if check_edit_perm:
        permission_string = check_edit_perm.values()[0]['Current_Permissions']
        permission_string = permission_string.replace("\'", "\"")
        permission_dict = json.loads(permission_string)
        flag = check_permission(string_list, permission_dict)
        if flag == True:
            access_status = 2
        else:
            if check_view_perm:
                permission_string = check_view_perm.values()[0]['Current_Permissions']
                permission_string = permission_string.replace("\'", "\"")
                permission_dict = json.loads(permission_string)
                flag = check_permission(string_list, permission_dict)
                if flag == True:
                    access_status = 1
                else:
                    access_status = 0
    return Response(access_status)


def get_child_object_id_list(project_version, migration_name, parent_id, output_list):
    temp_list = []
    child_data = ObjectTypes.objects.filter(Migration_Name=migration_name, Project_Version_Id=project_version,
                                            Parent_Object_Id=parent_id)
    for dict in child_data.values():
        object_id = dict['Object_Id']
        output_list.append(object_id)
        temp_list.append(object_id)
    if temp_list:
        for id in temp_list:
            get_child_object_id_list(project_version, migration_name, id, output_list)
    return output_list


@api_view(['GET', 'POST'])
def feature_approval_list(request):
    project_version = request.data['Project_Version_Id']
    migration_name = request.data['Migration_Name']
    parent_object = request.data['Parent_Object_Name']

    parent_data = ObjectTypes.objects.filter(Migration_Name=migration_name, Project_Version_Id=project_version,
                                             Object_Type=parent_object, Parent_Object_Id='')
    parent_id = parent_data.values()[0]['Object_Id']

    output_list = []
    output_list.append(parent_id)
    object_id_list = get_child_object_id_list(project_version, migration_name, parent_id, output_list)

    feature_data = Features.objects.filter(Project_Version_Id=project_version, Migration_Name=migration_name,
                                           Object_Id__in=object_id_list,
                                           Feature_version_approval_status__in=(
                                               'Approved', 'Awaiting Approval', 'Denied'))
    serializer = FeatureSerializer(feature_data, many=True)
    return Response(serializer.data)


@api_view(['GET', 'POST'])
def predecessor_list(request):
    object_id = request.data['Object_Id']
    features_data = Features.objects.filter(Object_Id=object_id)
    serializer = FeatureNameSerializer(features_data, many=True)
    return Response(serializer.data)


@api_view(['GET', 'POST'])
def table_features_list(request):
    object_id = request.data['Object_Id']
    features_data = Features.objects.filter(Object_Id=object_id)
    serializer = FeatureSerializer(features_data, many=True)
    return Response(serializer.data)


@api_view(['GET', 'POST'])
def feature_detail(request, feature_name):
    object_id = request.data['Object_Id']
    features_data = Features.objects.filter(Object_Id=object_id, Feature_Name=feature_name)
    serializer = FeatureSerializer(features_data, many=True)
    return Response(serializer.data)


@api_view(['GET', 'POST'])
def approval_requests_list(request):
    email = request.data['User_Email']
    migration_name = request.data['Migration_Name']
    parent_object = request.data['Parent_Object_Name']
    approvals_data = Approvals.objects.filter(Migration_Name=migration_name,
                                              Approval_Request__startswith=str(parent_object))
    serializer = ApprovalSerializer(approvals_data, many=True)
    return Response(serializer.data)


@api_view(['PUT'])
def feature_update(request, id):
    feature = Features.objects.get(Feature_Id=id)
    serializer = FeatureSerializer(instance=feature, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST', 'GET'])
def dynamicrulesadd(request):
    # migration_name = request.data['Migration_Name']
    # object_Type = request.data['Object_Type']
    user_email = request.data['User_Email']
    # input_field = request.data['input_field']
    # output_field = request.data['output_field']
    # rules_toapply = request.data['rules_toApply']
    # parent_object_type = request.data['Parent_Object_Type']
    # child_object_type = request.data['Child_Object_Type']
    serializer = DynamicRulesSerializer(data=request.data)
    existing_users = dynamicrules.objects.filter(User_Email=user_email)
    if existing_users:
        dynamicrules.objects.filter(User_Email=user_email).delete()
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def dymaic_rules_list(request):
    user_name = request.data['User_Email']
    att = dynamicrules.objects.filter(User_Email=user_name)
    serializer = DynamicRulesListSerializer(att, many=True)
    return Response(serializer.data)
