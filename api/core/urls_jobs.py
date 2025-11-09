from django.urls import path
from .views import ( 
                    JobViewSet, JobCategoryListCreateView,JobCategoryRetrieveUpdateDeleteView,
                    ApplyToJobView,UnapplyFromJobView,JobDiscoveryView,UpdateResponseFilesView,
                    ResponseListForJobView, AcceptFreelancerView, RejectFreelancerView,
                    JobsWithResponsesView,AdvancedJobSearchAPIView,AppliedJobsByFreelancerView,
                    ClientJobStatusView,DashboardSummaryView
                    
)
from api.payment.views import ProceedToPayAPIView


job_list = JobViewSet.as_view({'get': 'list'})
job_create = JobViewSet.as_view({'post': 'create'})
job_detail = JobViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'})
job_matches = JobViewSet.as_view({'get': 'matches'})
job_complete = JobViewSet.as_view({'patch': 'mark_completed'})
job_underreview = JobViewSet.as_view({'get': 'underreview'})
job_marked_for_review = JobViewSet.as_view({'patch': 'mark_for_review'})



urlpatterns = [
    
    path('search/', AdvancedJobSearchAPIView.as_view(), name='job-search'),
    
    path('discover/', JobDiscoveryView.as_view(), name='job-discovery-default'),
    
    #status
    #path('freelancer/',FreelancerJobStatusView.as_view(), name='freelancer-job-status'),
    path('by-client/',ClientJobStatusView.as_view(), name='client-job-status'),
    
    
    #dashboard
    path('dashboard/summary/', DashboardSummaryView.as_view(), name='dashboard-summary'),
    
    #job categories
    path('categories/', JobCategoryListCreateView.as_view(), name='jobcategory-list-create'),
    path('categories/<slug:slug>/', JobCategoryRetrieveUpdateDeleteView.as_view(), name='jobcategory-detail'),
    
    
    #Job list,detail,create
    path('list/', job_list, name='job-list'),
    path('create/', job_create, name='job-create'),
    path('<slug:slug>/', job_detail, name='job-detail-slug'),
    path('<slug:slug>/matches/', job_matches, name='job-matches'),
    path('<slug:slug>/complete/', job_complete, name='job-complete'),
    
    #apply and unapply
    path('<slug:slug>/apply/', ApplyToJobView.as_view(), name='job-apply'),
    path('<slug:slug>/unapply/', UnapplyFromJobView.as_view(), name='job-unapply'),
    path('<slug:slug>/update-files/', UpdateResponseFilesView.as_view(), name='update-response-files'),
    path('applied/by-freelancer/', AppliedJobsByFreelancerView.as_view(), name='applied-jobs'),

    

    path('<slug:slug>/aplications/', ResponseListForJobView.as_view(), name='job-applications'),
    path('<slug:slug>/applications/<slug:response_slug>/mark-for-review/',job_marked_for_review, name='job-mark-for-review'),
    path('<slug:slug>/underreview/', job_underreview, name='job-underreview'),
    path('<slug:slug>/accept/<str:identifier>/', AcceptFreelancerView.as_view(), name='accept-freelancer'),
    path('<slug:slug>/reject/<str:identifier>/', RejectFreelancerView.as_view(), name='reject-freelancer'),

    path('discover/<str:status_filter>/', JobDiscoveryView.as_view(), name='job-discovery'),
    
    path("<slug_or_id>/proceed-to-pay/", ProceedToPayAPIView.as_view(), name="proceed-to-pay"),
    path("<slug_or_id>/success/", ProceedToPayAPIView.as_view(), {"state": "success"}, name="payment-success"),
    path("<slug_or_id>/failed/", ProceedToPayAPIView.as_view(),{"state": "failed"}, name="payment-failed"),

]
