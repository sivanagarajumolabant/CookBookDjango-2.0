from django.urls import path
from django.conf.urls.static import static
from . import views
from .views import *

urlpatterns = [
                  # User registration Api's
                  path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
                  path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPI.as_view(),
                       name='password-reset-confirm'),
                  path('request-reset-email/', RequestPasswordResetEmail.as_view(), name='request-reset-email'),
                  path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
                  path('register/', RegisterView.as_view(), name='auth_register'),
                  path('resendemail/', ResendVerifyEmail.as_view()),

                  # Migration Api's
                  path('migrationcreate/', views.migrationcreate, name='migrationcreate'),
                  path('migration_names_list/', views.migration_names_list, name='migration_names_list'),
                  path('project_versions_list/', views.project_versions_list, name='project_versions_list'),

                  # Object types Api's
                  path('object_type_create/', views.object_type_create, name='object_type_create'),
                  path('parent_object_list/', views.parent_object_list, name='parent_object_list'),
                  path('object_types_format/', views.object_types_format, name='object_types_format'),

                  # Feature Api's
                  path('featurecreate/', views.featurecreate, name='featurecreate'),

                  # Approval Api's
                  path('approval_request_create/', views.approval_request_create, name='approval_request_create'),

                  # Permission Api's
                  path('permission_create/', views.permission_create, name='permission_create'),

                  # Menu Creation Api's
                  path('menu_view_creation/', views.menu_view_creation, name='menu_view_creation'),

                  # Dynamic Rules implementation Api's
                  path('dynamic_rules_creation/', views.dynamicrulesadd, name='dynamic_rules_creation'),
                  path('dyanmic_rules_list/', views.dymaic_rules_list, name="dynamic_rules_list"),

                  # feature catalog api's
                  path('features_list/', views.features_list, name='features_list'),
                  path('check_user_access/', views.check_user_access, name='check_user_access'),
                  # Feature Approvals Api's
                  path('feature_approvals_list/', views.feature_approval_list, name='feature_approvals_list'),
                  path('predecessor_list/', views.predecessor_list, name='predecessor_list'),
                  path('table_features_list/', views.table_features_list, name='table_features_list'),
                  path('feature_detail/<str:feature_name>/', views.feature_detail, name='feature_detail'),
                  # admin approvals list
                  path('approval_requests_list/', views.approval_requests_list, name='approval_requests_list'),
                  path('feature_update/<int:id>/', views.feature_update,name='feature_update'),

              ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
