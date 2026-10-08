import sys
sys.path.insert(0, 'mad-ps-explanation-service')
from database import shared_db

inc = {
    'incident_id': 'INC-20260904-AFEBE9',
    'report_id': 'REP-INC-20260904-AFEBE9',
    'incident_category': 'SQL_INJECTION',
    'risk_score': 9.2,
    'risk_severity_band': 'CRITICAL',
    'executive_summary': 'An unauthenticated attacker executed an AST syntax-breaking SQL injection against /api/v1/orders to dump user account hashes.',
    'detection_mesh_confidence': 0.96,
    'contributing_branch_scores': {
        'svm_branch': 0.94,
        'dnn_branch': 0.96,
        'statistical_anomaly': 0.88,
        'semantic_payload_evaluator': 0.97,
        'stateful_sequence_tracker': 0.95,
        'graph_correlation': 0.82,
        'rate_frequency_anomaly': 0.90,
        'behavioral_identity_abuse': 0.89
    },
    'raw_log_details': {
        'timestamp': '2026-09-04T14:32:01.402Z',
        'method': 'POST',
        'path': '/api/v1/orders',
        'source_ip': '198.51.100.42',
        'payload': "order_id=1042' UNION SELECT username, password_hash FROM admin_users--"
    },
    'consensus_score': 94.2,
    'requires_human_approval': True,
    'human_approval_reasoning': 'Automated schema patch deployment to production database gateway requires L2 operator authorization.',
    'ranked_actions': [
        {
            'action_id': 'ACT-01',
            'priority': 'P0_IMMEDIATE',
            'category': 'CONTAINMENT',
            'title': 'Isolate Origin IP and Revoke Active Sessions',
            'description': 'Inject WAF rate drop rule for 198.51.100.42 and invalidate active token pool.',
            'requires_human_approval': False
        },
        {
            'action_id': 'ACT-02',
            'priority': 'P1_HIGH',
            'category': 'ARCHITECTURAL_PREVENTION',
            'title': 'Deploy Parameterized Query Filter on /api/v1/orders',
            'description': 'Replace dynamic string concatenation with AST prepared statements.',
            'requires_human_approval': True,
            'approval_reasoning': 'Modifies gateway query parser rules.'
        }
    ]
}

shared_db.save_incident_report(inc)
print('Successfully saved incident INC-20260904-AFEBE9 into shared_db!')
